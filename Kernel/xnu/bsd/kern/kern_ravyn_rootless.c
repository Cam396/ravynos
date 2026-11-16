/*
 * Opt-in Big Sur rootless, task-access, and Recovery compatibility.
 * Restricted vnode enforcement backs the file-write-data query. Launchd
 * queries are scoped to the actual process and credentials. The Recovery
 * profile also answers the observed Data-volume access queries and can trust
 * pinned platform signatures for the observed service and device requests.
 * General Sandbox profile installation remains unsupported.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/file_internal.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/random.h>
#include <sys/sysctl.h>
#include <mach/vm_prot.h>
#include <sys/proc.h>
#include <sys/proc_internal.h>
#include <sys/proc_info.h>
#include <sys/kauth.h>
#include <sys/stat.h>
#include <sys/vnode.h>
#include <sys/vnode_internal.h>
#include <sys/csr.h>
#include <sys/codesign.h>
#include <sys/priv.h>
#include <IOKit/IOBSD.h>
#include <kern/task.h>
#include <security/mac_policy.h>
#include <security/mac_framework.h>
#include <pexpert/pexpert.h>
#include <libkern/section_keywords.h>

#if CONFIG_MACF

#if defined(__arm64__) && defined(ARM64_BOARD_CONFIG_BCM2837)
static char ravyn_recovery_sandbox_sentinel[32];
SYSCTL_DECL(_security_mac);
SYSCTL_NODE(_security_mac, OID_AUTO, sandbox,
    CTLFLAG_RD | CTLFLAG_LOCKED | CTLFLAG_NOAUTO, 0, "Recovery sandbox compatibility");
SYSCTL_STRING(_security_mac_sandbox, OID_AUTO, sentinel,
    CTLFLAG_RD | CTLFLAG_LOCKED | CTLFLAG_NOAUTO,
    ravyn_recovery_sandbox_sentinel, 0, "Boot-local suffix for atomic temporary names");

static void
ravyn_recovery_sandbox_sentinel_init(void)
{
	static const char prefix[] = ".ravyn-";
	static const char digits[] = "0123456789abcdef";
	uint8_t entropy[12];
	char *suffix = ravyn_recovery_sandbox_sentinel + sizeof(prefix) - 1;

	read_random(entropy, sizeof(entropy));
	memcpy(ravyn_recovery_sandbox_sentinel, prefix, sizeof(prefix) - 1);
	for (unsigned i = 0; i < sizeof(entropy); i++) {
		suffix[2 * i] = digits[entropy[i] >> 4];
		suffix[2 * i + 1] = digits[entropy[i] & 0xf];
	}
	suffix[2 * sizeof(entropy)] = 0;
	sysctl_register_oid(&sysctl__security_mac_sandbox);
	sysctl_register_oid(&sysctl__security_mac_sandbox_sentinel);
}
#endif

#define RAVYN_ROOTLESS_QUERY_SELECTOR 2
#define RAVYN_RECOVERY_PASSTHROUGH_SELECTOR 12
#define RAVYN_RECOVERY_PASSTHROUGH_WRITE 0x102ULL
#define RAVYN_ROOTLESS_QUERY_FILTER   0xf0ULL
#define RAVYN_ROOTLESS_QUERY_FLAGS    0x20000005ULL
#define RAVYN_AUDIT_QUERY_FLAGS       0x40000000ULL
#define RAVYN_RECOVERY_XPC_NAME_FILTER 50

/* Layout recovered from Big Sur 11.6's rootless_check_trusted_fd helper. */
struct ravyn_rootless_query {
	uint64_t result;
	uint64_t pid;
	uint64_t operation;
	uint64_t filter;
	uint64_t fd;
	uint64_t flags;
	uint64_t reserved[7];
};

static int
ravyn_rootless_protection_active(void)
{
#if CONFIG_CSR
	return csr_check(CSR_ALLOW_UNRESTRICTED_FS) != 0;
#else
	/* Builds without CSR retain the default protected-filesystem behavior. */
	return 1;
#endif
}

static int
ravyn_vnode_is_restricted(vnode_t vp, uint32_t *flags)
{
	struct vnode_attr va;
	int error;

	*flags = 0;
	VATTR_INIT(&va);
	VATTR_WANTED(&va, va_flags);
	error = vnode_getattr(vp, &va, vfs_context_current());
	if (error != 0) {
		return error;
	}
	if (!VATTR_IS_SUPPORTED(&va, va_flags)) {
		return EOPNOTSUPP;
	}
	*flags = va.va_flags;
	return 0;
}

/*
 * Big Sur's audit-token query carries a subject PID plus its exec generation.
 * A process may ask about itself; only launchd may broker a query for another
 * subject. Evaluate kernel credentials and MAC proc-info policy, never claimed
 * audit-token UIDs or an executable name. This limited policy grants only root
 * process inspection and service creation; it does not load or claim Sandbox
 * profiles. A job-creation answer is this experiment's root-only rule, not an
 * emulation of Apple's private profile/entitlement policy.
 */
static int
ravyn_audit_query(struct proc *p, struct ravyn_rootless_query *query,
	int process_info)
{
	proc_t subject;
	kauth_cred_t cred;
	uint64_t denied = 1;
	unsigned int i;
	int error = 0;

	if (query->filter != 0 || query->fd != 0 ||
	    query->flags != RAVYN_AUDIT_QUERY_FLAGS) {
		return ENOPOLICY;
	}
	if (query->pid == 0 || query->pid > INT_MAX ||
	    query->reserved[0] == 0 || query->reserved[0] > UINT32_MAX) {
		return EINVAL;
	}
	for (i = 1; i < sizeof(query->reserved) / sizeof(query->reserved[0]); i++) {
		if (query->reserved[i] != 0) {
			return ENOPOLICY;
		}
	}
	if (query->pid != (uint64_t)proc_pid(p) && proc_pid(p) != 1) {
		return EPERM;
	}
	subject = proc_find((int)query->pid);
	if (subject == PROC_NULL) {
		return ESRCH;
	}
	if ((uint32_t)proc_pidversion(subject) != (uint32_t)query->reserved[0]) {
		proc_rele(subject);
		return ESRCH;
	}
	cred = kauth_cred_proc_ref(subject);
	if (kauth_cred_issuser(cred)) {
		if (process_info) {
			/* Preserve the existing MAC check for inspecting the broker. */
			error = mac_proc_check_proc_info(subject, p,
			    PROC_INFO_CALL_PIDINFO, PROC_PIDTBSDINFO);
			if (error == 0) {
				denied = 0;
			}
		} else {
			kauth_cred_t broker_cred = kauth_cred_proc_ref(p);

			/*
			 * A privileged submitter may ask a privileged launchd to
			 * create a service. This advisory query never authorizes
			 * fork/exec or changes the service's rootless trust.
			 */
			if (kauth_cred_issuser(broker_cred)) {
				denied = 0;
			}
			kauth_cred_unref(&broker_cred);
		}
	}
	kauth_cred_unref(&cred);
	proc_rele(subject);
	return copyout(&denied, (user_addr_t)query->result, sizeof(denied));
}

static int
ravyn_recovery_hfs_enabled(void)
{
	int recovery = 0;
	return PE_parse_boot_argn("ravyn_recovery_hfs", &recovery, sizeof(recovery)) && recovery;
}

#if defined(__arm64__) && defined(ARM64_BOARD_CONFIG_BCM2837)
static bool ravyn_recovery_read_client(struct proc *, kauth_cred_t);

static bool
ravyn_recovery_preferences_enabled(void)
{
    int enabled = 0;
    return ravyn_recovery_hfs_enabled() &&
        PE_parse_boot_argn("ravyn_recovery_preferences_read", &enabled, sizeof(enabled)) &&
        enabled == 1;
}
#endif

static int
ravyn_recovery_check_vnode_access(vnode_t vp, vfs_context_t ctx, kauth_cred_t file_cred, bool write)
{
	mount_t mount = vnode_mount(vp);
	bool directory_read = false;
#if defined(__arm64__) && defined(ARM64_BOARD_CONFIG_BCM2837)
	directory_read = !write && vnode_isdir(vp) && ravyn_recovery_preferences_enabled();
#endif
	if (mount == NULL || (!vnode_isreg(vp) && !directory_read)) {
		return EINVAL;
	}
	const struct vfsstatfs *stats = vfs_statfs(mount);
	if (strcmp(stats->f_fstypename, "hfs") != 0 ||
	    strcmp(stats->f_mntfromname, "/dev/md1") != 0 ||
	    strcmp(stats->f_mntonname, "/System/Volumes/Data") != 0) {
		return ENOPOLICY;
	}
	if (write && vfs_isrdonly(mount)) {
		return EROFS;
	}

	kauth_action_t action = write ? KAUTH_VNODE_WRITE_DATA : KAUTH_VNODE_READ_DATA;
	int error = vnode_authorize(vp, NULL, action, ctx);
	if (error == 0) {
		error = directory_read ? mac_vnode_check_readdir(ctx, vp) :
		    (write ? mac_vnode_check_write(ctx, file_cred, vp) :
		    mac_vnode_check_read(ctx, file_cred, vp));
	}
	return error;
}

/*
 * Big Sur CoreFoundation passes an already-open descriptor and the observed
 * 0x102 write query. Evaluate the existing write authorization on the
 * Recovery Data volume. CoreFoundation opens the descriptor read-only to
 * identify the vnode, then makes a separate write. This query leaves descriptor
 * modes and normal write authorization untouched.
 */
static int
ravyn_recovery_passthrough_write(struct proc *p, user_addr_t arg)
{
	if (!ravyn_recovery_hfs_enabled()) {
		return ENOPOLICY;
	}

	struct {
		int64_t fd;
		uint64_t access;
	} request;
	int error = copyin(arg, &request, sizeof(request));
	if (error) {
		return error;
	}
	if (request.access != RAVYN_RECOVERY_PASSTHROUGH_WRITE) {
		return ENOPOLICY;
	}
	if (request.fd < 0 || request.fd > INT_MAX) {
		return EBADF;
	}

	vfs_context_t ctx = vfs_context_current();
	if (p != current_proc() || !kauth_cred_issuser(vfs_context_ucred(ctx))) {
		return EPERM;
	}

	struct fileproc *fp = NULL;
	vnode_t vp = NULL;
	int fd = (int)request.fd;
	error = fp_getfvp(p, fd, &fp, &vp);
	if (error) {
		return error;
	}
	error = vnode_getwithref(vp);
	if (error) {
		goto out;
	}

	error = ravyn_recovery_check_vnode_access(vp, ctx, fp->f_fglob->fg_cred, true);
	vnode_put(vp);
out:
	(void)fp_drop(p, fd, fp, 0);
	return error;
}

/*
 * CoreFoundation and Security's atomic database routines query the current
 * process's access to an existing file. Resolve the live vnode and use
 * ordinary VFS/MAC authorization. The audit-token form also checks generation.
 */
static int
ravyn_recovery_path_access(struct proc *p, const struct ravyn_rootless_query *query,
    bool audited, bool write)
{
	if (!ravyn_recovery_hfs_enabled() || query->pid != (uint64_t)proc_pid(p) ||
	    query->reserved[0] != (audited ? (uint32_t)proc_pidversion(p) : 0)) {
		return ENOPOLICY;
	}
	for (unsigned i = 1; i < 7; i++) {
		if (query->reserved[i] != 0) {
			return ENOPOLICY;
		}
	}

	vfs_context_t ctx = vfs_context_current();
	kauth_cred_t cred = vfs_context_ucred(ctx);
	uint64_t denied = 1;
	bool client_allowed = p == current_proc() && kauth_cred_issuser(cred);
#if defined(__arm64__) && defined(ARM64_BOARD_CONFIG_BCM2837)
	if (!write && ravyn_recovery_preferences_enabled()) {
		client_allowed = ravyn_recovery_read_client(p, cred);
	}
#endif
	if (client_allowed) {
		char path[MAXPATHLEN];
		size_t copied = 0;
		int error = copyinstr((user_addr_t)query->fd, path, sizeof(path), &copied);
		if (error) {
			return error;
		}
		if (path[0] != '/') {
			return EINVAL;
		}

		vnode_t vp = NULL;
		error = vnode_lookup(path, VNODE_LOOKUP_NOFOLLOW, &vp, ctx);
		if (error == 0) {
			denied = ravyn_recovery_check_vnode_access(vp, ctx, cred, write) != 0;
			vnode_put(vp);
		}
	}
	return copyout(&denied, (user_addr_t)query->result, sizeof(denied));
}

#if defined(__arm64__) && defined(ARM64_BOARD_CONFIG_BCM2837)
/*
 * The native preference-domain filter asks whether this process can read a
 * system preference domain. Do not answer for writes, other processes, or
 * arbitrary paths. Resolve the real Data-volume plist (or its containing
 * directory when absent), and retain ordinary VFS/MAC read authorization.
 */
static int
ravyn_recovery_preference_read(struct proc *p, const struct ravyn_rootless_query *query)
{
    if (!ravyn_recovery_preferences_enabled()) {
        return ENOPOLICY;
    }
    bool audited = query->flags == (RAVYN_AUDIT_QUERY_FLAGS | 0x11);
    if (p != current_proc() || query->pid != (uint64_t)proc_pid(p) ||
        query->reserved[0] != (audited ? (uint32_t)proc_pidversion(p) : 0)) {
        return ENOPOLICY;
    }
    for (unsigned i = 1; i < 7; i++) {
        if (query->reserved[i]) {
            return ENOPOLICY;
        }
    }
    char domain[256];
    size_t length = 0;
    int error = copyinstr((user_addr_t)query->fd, domain, sizeof(domain), &length);
    if (error) {
        return error;
    }
    if (length <= 1 || length > 249) {
        return EINVAL;
    }
    for (unsigned i = 0; i + 1 < length; i++) {
        unsigned char c = domain[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-')) {
            return EINVAL;
        }
        if (c == '.' && i && domain[i - 1] == '.') {
            return EINVAL;
        }
    }
    const char *name = strcmp(domain, "kCFPreferencesAnyApplication") == 0 ?
        ".GlobalPreferences" : domain;
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
        return EINVAL;
    }
    vfs_context_t ctx = vfs_context_current();
    uint64_t denied = 1;
    if (ravyn_recovery_read_client(p, vfs_context_ucred(ctx))) {
        char path[MAXPATHLEN];
        snprintf(path, sizeof(path), "/Library/Preferences/%s.plist", name);
        vnode_t vp = NULL;
        error = vnode_lookup(path, VNODE_LOOKUP_NOFOLLOW, &vp, ctx);
        if (error == ENOENT) {
            error = vnode_lookup("/Library/Preferences", VNODE_LOOKUP_NOFOLLOW, &vp, ctx);
        }
        if (error == 0) {
            denied = ravyn_recovery_check_vnode_access(vp, ctx, vfs_context_ucred(ctx), false) != 0;
            vnode_put(vp);
        }
    }
#if DEBUG || DEVELOPMENT
    static unsigned logs;
    if (__sync_fetch_and_add(&logs, 1) < 24) {
        printf("RAVYN-PREFERENCE-READ pid=%d domain=%s denied=%llu\n",
            proc_pid(p), domain, denied);
    }
#endif
    return copyout(&denied, (user_addr_t)query->result, sizeof(denied));
}
#endif

#if defined(__arm64__) && defined(ARM64_BOARD_CONFIG_BCM2837)
static int ravyn_recovery_service_access(struct proc *, const struct ravyn_rootless_query *, bool);
static int ravyn_recovery_sandbox_presence(const struct ravyn_rootless_query *);

#if DEBUG || DEVELOPMENT
/* Diagnostic only: no authorization decisions use these process-name labels. */
static bool
ravyn_recovery_trace_ui_query(struct proc *caller,
    const struct ravyn_rootless_query *query, const char *operation)
{
    int enabled = 0;
    if ((strcmp(operation, "mach-lookup") != 0 && strcmp(operation, "mach-register") != 0) ||
        !PE_parse_boot_argn("ravyn_recovery_ui_trace", &enabled, sizeof(enabled)) || enabled != 1 ||
        query->pid > INT_MAX || (query->filter != 6 && query->filter != 7)) {
        return false;
    }
    int pid = query->pid ? (int)query->pid : proc_pid(caller);
    proc_t subject = proc_find(pid);
    if (subject == PROC_NULL) {
        return false;
    }
    char name[MAXCOMLEN + 1];
    proc_lock(subject);
    memcpy(name, subject->p_comm, sizeof(name));
    proc_unlock(subject);
    name[MAXCOMLEN] = 0;
    proc_rele(subject);
    unsigned int slot;
    if (strcmp(name, "Recovery Springb") == 0) {
        slot = 0;
    } else if (strcmp(name, "Boot Picker") == 0) {
        slot = 1;
    } else if (strcmp(name, "KeyRecoveryAssis") == 0) {
        slot = 2;
    } else if (strcmp(name, "Installer Progre") == 0) {
        slot = 3;
    } else if (strcmp(name, "diskarbitrationd") == 0) {
        slot = 4;
    } else {
        return false;
    }
    char service[128];
    size_t copied = 0;
    int error = copyinstr((user_addr_t)query->fd, service, sizeof(service), &copied);
    const bool critical = error == 0 && (strcmp(service, "com.apple.recoveryos_agent") == 0 ||
        strcmp(service, "com.apple.InstallerProgress") == 0 ||
        strcmp(service, "com.apple.lsd.mapdb") == 0 ||
        strcmp(service, "com.apple.lsd.modifydb") == 0 ||
        strcmp(service, "com.apple.DiskArbitration.diskarbitrationd") == 0 ||
        (slot == 4 && (strcmp(service, "com.apple.SystemConfiguration.configd") == 0 ||
            strcmp(service, "com.apple.system.notification_center") == 0)) ||
        strcmp(operation, "mach-register") == 0);
    static volatile unsigned int count[5], critical_count[5];
    if (critical ? __sync_fetch_and_add(&critical_count[slot], 1) >= 24 :
        __sync_fetch_and_add(&count[slot], 1) >= 80) {
        return false;
    }
    if (error) {
        printf("RAVYN-UI-QUERY caller=%d subject=%llu name=%s operation=%s filter=%llu flags=%#llx generation=%llu name_error=%d\n",
            proc_pid(caller), query->pid, name, operation, query->filter, query->flags,
            query->reserved[0], error);
    } else {
        printf("RAVYN-UI-QUERY caller=%d subject=%llu name=%s operation=%s filter=%llu flags=%#llx generation=%llu service=%s\n",
            proc_pid(caller), query->pid, name, operation, query->filter, query->flags,
            query->reserved[0], service);
    }
    return true;
}

static void
ravyn_recovery_trace_ui_result(const struct ravyn_rootless_query *query, int result)
{
    uint64_t denied = UINT64_MAX;
    int read_error = result ? 0 :
        copyin((user_addr_t)query->result, &denied, sizeof(denied));
    printf("RAVYN-UI-RESULT subject=%llu provider_error=%d result_read_error=%d denied=%#llx\n",
        query->pid, result, read_error, denied);
}
#endif
#endif

static int
ravyn_rootless_policy_syscall(struct proc *p, int call, user_addr_t arg)
{
	struct ravyn_rootless_query query;
	struct fileproc *fp = NULL;
	vnode_t vp = NULL;
	char operation[32];
	size_t copied = 0;
	uint64_t denied = 0;
	uint32_t vnode_flags = 0;
	int error;
	unsigned int i;

	if (call == RAVYN_RECOVERY_PASSTHROUGH_SELECTOR) {
		return p == NULL ? ENOPOLICY : ravyn_recovery_passthrough_write(p, arg);
	}
	if (call != RAVYN_ROOTLESS_QUERY_SELECTOR) {
		return ENOPOLICY;
	}
	if (arg == 0) {
		return EINVAL;
	}
	error = copyin(arg, &query, sizeof(query));
	if (error != 0) {
		return error;
	}

	if (p == NULL) {
		return ENOPOLICY;
	}
	if (query.result == 0) {
		return EINVAL;
	}
	if (query.operation == 0) {
#if defined(__arm64__) && defined(ARM64_BOARD_CONFIG_BCM2837)
		return ravyn_recovery_sandbox_presence(&query);
#else
		return EINVAL;
#endif
	}
	error = copyinstr((user_addr_t)query.operation, operation,
	    sizeof(operation), &copied);
	if (error != 0) {
		return error;
	}
#if defined(__arm64__) && defined(ARM64_BOARD_CONFIG_BCM2837) && (DEBUG || DEVELOPMENT)
    bool trace_ui = ravyn_recovery_trace_ui_query(p, &query, operation);
#endif
#if defined(__arm64__) && (DEBUG || DEVELOPMENT)
	int trace = 0;
	if ((strcmp(p->p_comm, "pmset") == 0 || strcmp(p->p_comm, "cfprefsd") == 0 ||
	     strcmp(p->p_comm, "security") == 0 || strcmp(p->p_comm, "securityd") == 0) &&
	    PE_parse_boot_argn("ravyn_recovery_prefs_trace", &trace, sizeof(trace)) && trace) {
		printf("RAVYN-PREFS-SBX comm=%s operation=%s subject=%llu filter=0x%llx value=0x%llx flags=0x%llx generation=0x%llx\n",
		    p->p_comm, operation, query.pid, query.filter, query.fd, query.flags,
		    query.reserved[0]);
	}
	if (strcmp(operation, "mach-lookup") == 0 && query.filter == 6 &&
	    (p == initproc || strcmp(p->p_comm, "recoveryosd") == 0) &&
	    PE_parse_boot_argn("ravyn_recovery_prefs_trace", &trace, sizeof(trace)) && trace) {
		char service[128];
		size_t service_length = 0;
		if (copyinstr((user_addr_t)query.fd, service, sizeof(service), &service_length) == 0 &&
		    strcmp(service, "com.apple.SecurityServer") == 0) {
			printf("RAVYN-SECURITY-LOOKUP comm=%s subject=%llu flags=%#llx gen=%#llx\n",
			    p->p_comm, query.pid, query.flags, query.reserved[0]);
		}
	}
#endif
#if defined(__arm64__) && defined(ARM64_BOARD_CONFIG_BCM2837)
	if (((query.filter == 6 && (query.flags == RAVYN_AUDIT_QUERY_FLAGS || query.flags == 0)) ||
	    (query.filter == RAVYN_RECOVERY_XPC_NAME_FILTER && query.flags == RAVYN_AUDIT_QUERY_FLAGS)) &&
	    strcmp(operation, "mach-lookup") == 0) {
		int lookup = ravyn_recovery_service_access(p, &query, false);
#if DEBUG || DEVELOPMENT
        if (trace_ui) {
            ravyn_recovery_trace_ui_result(&query, lookup);
        }
#endif
		if (lookup != ENOPOLICY) {
			return lookup;
		}
	}
	if (query.filter == 7 && query.flags == RAVYN_AUDIT_QUERY_FLAGS &&
	    strcmp(operation, "mach-register") == 0) {
		int registration = ravyn_recovery_service_access(p, &query, true);
#if DEBUG || DEVELOPMENT
        if (trace_ui) {
            ravyn_recovery_trace_ui_result(&query, registration);
        }
#endif
		if (registration != ENOPOLICY) {
			return registration;
		}
	}
#endif
#if defined(__arm64__) && defined(ARM64_BOARD_CONFIG_BCM2837)
	if (query.filter == 0x1c && (query.flags == 0x11 ||
	    query.flags == (RAVYN_AUDIT_QUERY_FLAGS | 0x11)) &&
	    strcmp(operation, "user-preference-read") == 0) {
		return ravyn_recovery_preference_read(p, &query);
	}
#endif

	if (copied == sizeof("process-info-pidinfo") &&
	    strcmp(operation, "process-info-pidinfo") == 0) {
		return ravyn_audit_query(p, &query, 1);
	}
	if (copied == sizeof("job-creation") &&
	    strcmp(operation, "job-creation") == 0) {
		return ravyn_audit_query(p, &query, 0);
	}
	if (query.filter == 1 && query.flags == 0x40000013ULL &&
	    strcmp(operation, "file-write-data") == 0) {
		return ravyn_recovery_path_access(p, &query, true, true);
	}
	if (query.filter == 1 && query.flags == 1) {
		if (strcmp(operation, "file-read-data") == 0) {
			return ravyn_recovery_path_access(p, &query, false, false);
		}
		if (strcmp(operation, "file-write-data") == 0) {
			return ravyn_recovery_path_access(p, &query, false, true);
		}
	}
	if (query.pid != 1 || query.filter != RAVYN_ROOTLESS_QUERY_FILTER ||
	    query.flags != RAVYN_ROOTLESS_QUERY_FLAGS) {
		return ENOPOLICY;
	}
	if (query.result == 0 || query.operation == 0 || query.fd > INT_MAX) {
		return EINVAL;
	}
	for (i = 0; i < (unsigned int)(sizeof(query.reserved) / sizeof(query.reserved[0])); i++) {
		if (query.reserved[i] != 0) {
			return ENOPOLICY;
		}
	}
	if (copied != sizeof("file-write-data") ||
	    strcmp(operation, "file-write-data") != 0) {
		return ENOPOLICY;
	}
	if (!ravyn_rootless_protection_active()) {
		return copyout(&denied, (user_addr_t)query.result, sizeof(denied));
	}

	error = fp_getfvp(p, (int)query.fd, &fp, &vp);
	if (error != 0) {
		return error;
	}
	error = vnode_getwithref(vp);
	if (error == 0) {
		error = ravyn_vnode_is_restricted(vp, &vnode_flags);
		if (error == 0 && (vnode_flags & SF_RESTRICTED) != 0) {
			denied = 1;
		}
		vnode_put(vp);
	}
	(void)fp_drop(p, (int)query.fd, fp, 0);
	if (error != 0) {
		return error;
	}
	error = copyout(&denied, (user_addr_t)query.result, sizeof(denied));
	return error;
}

/*
 * The seeded restricted bit is an integrity boundary in this limited policy.
 * Guard each mutation route at its documented MAC hook. In particular, vnode
 * write checks do not cover truncation, metadata, rename, or shared mmap.
 * This does not implement Apple's rootless exceptions or Sandbox profiles.
 */
static int
ravyn_vnode_check_mutation(struct vnode *vp)
{
	uint32_t vnode_flags = 0;
	int error;

	if (!ravyn_rootless_protection_active()) {
		return 0;
	}
	error = ravyn_vnode_is_restricted(vp, &vnode_flags);
	if (error != 0) {
		return error;
	}
	return (vnode_flags & SF_RESTRICTED) != 0 ? EPERM : 0;
}

static int
ravyn_vnode_check_write(kauth_cred_t active_cred __unused,
	kauth_cred_t file_cred __unused, struct vnode *vp,
	struct label *label __unused)
{
	return ravyn_vnode_check_mutation(vp);
}

static int
ravyn_vnode_check_open(kauth_cred_t cred __unused, struct vnode *vp,
	struct label *label __unused, int acc_mode)
{
	/* Compound open may truncate before the standalone truncate hook. */
	return (acc_mode & O_TRUNC) != 0 ? ravyn_vnode_check_mutation(vp) : 0;
}

static int
ravyn_vnode_check_setflags(kauth_cred_t cred __unused, struct vnode *vp,
	struct label *label __unused, u_long flags)
{
	if (!ravyn_rootless_protection_active()) {
		return 0;
	}
	/* Only the offline root builder seeds trust in this experiment. */
	if ((flags & SF_RESTRICTED) != 0) {
		return EPERM;
	}
	return ravyn_vnode_check_mutation(vp);
}

static int
ravyn_vnode_check_setattrlist(kauth_cred_t cred __unused, struct vnode *vp,
	struct label *label __unused, struct attrlist *alist __unused)
{
	return ravyn_vnode_check_mutation(vp);
}

static int
ravyn_vnode_check_setacl(kauth_cred_t cred __unused, struct vnode *vp,
	struct label *label __unused, struct kauth_acl *acl __unused)
{
	return ravyn_vnode_check_mutation(vp);
}

static int
ravyn_vnode_check_setextattr(kauth_cred_t cred __unused, struct vnode *vp,
	struct label *label __unused, const char *name __unused,
	struct uio *uio __unused)
{
	return ravyn_vnode_check_mutation(vp);
}

static int
ravyn_vnode_check_deleteextattr(kauth_cred_t cred __unused, struct vnode *vp,
	struct label *label __unused, const char *name __unused)
{
	return ravyn_vnode_check_mutation(vp);
}

static int
ravyn_vnode_check_setmode(kauth_cred_t cred __unused, struct vnode *vp,
	struct label *label __unused, mode_t mode __unused)
{
	return ravyn_vnode_check_mutation(vp);
}

static int
ravyn_vnode_check_setowner(kauth_cred_t cred __unused, struct vnode *vp,
	struct label *label __unused, uid_t uid __unused, gid_t gid __unused)
{
	return ravyn_vnode_check_mutation(vp);
}

static int
ravyn_vnode_check_setutimes(kauth_cred_t cred __unused, struct vnode *vp,
	struct label *label __unused, struct timespec atime __unused,
	struct timespec mtime __unused)
{
	return ravyn_vnode_check_mutation(vp);
}

static int
ravyn_vnode_check_create(kauth_cred_t cred __unused, struct vnode *dvp,
	struct label *dlabel __unused, struct componentname *cnp __unused,
	struct vnode_attr *vap)
{
	int error;

	error = ravyn_vnode_check_mutation(dvp);
	if (error != 0) {
		return error;
	}
	if (ravyn_rootless_protection_active() && vap != NULL &&
	    VATTR_IS_ACTIVE(vap, va_flags) &&
	    (vap->va_flags & SF_RESTRICTED) != 0) {
		return EPERM;
	}
	return 0;
}

static int
ravyn_vnode_check_namespace(kauth_cred_t cred __unused, struct vnode *dvp,
	struct label *dlabel __unused, struct vnode *vp,
	struct label *label __unused, struct componentname *cnp __unused)
{
	int error;

	error = ravyn_vnode_check_mutation(dvp);
	if (error == 0 && vp != NULL) {
		error = ravyn_vnode_check_mutation(vp);
	}
	return error;
}

static int
ravyn_vnode_check_clone(kauth_cred_t cred __unused, struct vnode *dvp,
	struct label *dlabel __unused, struct vnode *vp __unused,
	struct label *label __unused, struct componentname *cnp __unused)
{
	/* The VFS strips SF_RESTRICTED from source flags on a new clone. */
	return ravyn_vnode_check_mutation(dvp);
}

static int
ravyn_vnode_check_rename(kauth_cred_t cred __unused, struct vnode *dvp,
	struct label *dlabel __unused, struct vnode *vp,
	struct label *label __unused, struct componentname *cnp __unused,
	struct vnode *tdvp, struct label *tdlabel __unused, struct vnode *tvp,
	struct label *tlabel __unused, struct componentname *tcnp __unused)
{
	int error;

	error = ravyn_vnode_check_mutation(dvp);
	if (error == 0) {
		error = ravyn_vnode_check_mutation(vp);
	}
	if (error == 0) {
		error = ravyn_vnode_check_mutation(tdvp);
	}
	if (error == 0 && tvp != NULL) {
		error = ravyn_vnode_check_mutation(tvp);
	}
	return error;
}

static int
ravyn_vnode_check_exchangedata(kauth_cred_t cred __unused, struct vnode *v1,
	struct label *vl1 __unused, struct vnode *v2,
	struct label *vl2 __unused)
{
	int error;

	error = ravyn_vnode_check_mutation(v1);
	return error != 0 ? error : ravyn_vnode_check_mutation(v2);
}

static int
ravyn_file_check_mmap(kauth_cred_t cred __unused, struct fileglob *fg,
	struct label *label __unused, int prot, int flags,
	uint64_t file_pos __unused, int *maxprot)
{
	uint32_t vnode_flags = 0;
	int error;

	if (!ravyn_rootless_protection_active() || (flags & MAP_SHARED) == 0 ||
	    FILEGLOB_DTYPE(fg) != DTYPE_VNODE) {
		return 0;
	}
	/* mmap() holds an iocount on this fileglob's vnode across this hook. */
	error = ravyn_vnode_is_restricted((vnode_t)fg->fg_data, &vnode_flags);
	if (error != 0) {
		return error;
	}
	if ((vnode_flags & SF_RESTRICTED) == 0) {
		return 0;
	}
	/* Prevent a read-only shared mapping being upgraded by mprotect(). */
	*maxprot &= ~VM_PROT_WRITE;
	return (prot & VM_PROT_WRITE) != 0 ? EPERM : 0;
}

#if defined(__arm64__) && defined(ARM64_BOARD_CONFIG_BCM2837)
/* SHA-256 CodeDirectory hashes from the pinned 20G165 BaseSystem trust cache. */
static const uint8_t ravyn_windowserver_cdhash[CS_CDHASH_LEN] = {
	0xaa, 0x64, 0x13, 0xc3, 0x3d, 0x4a, 0x89, 0xdf, 0x21, 0x83,
	0x30, 0x53, 0x44, 0x3b, 0x78, 0x0a, 0x58, 0x9a, 0xa2, 0x91,
};

static const uint8_t ravyn_objc_trampolines_cdhash[CS_CDHASH_LEN] = {
	0xff, 0x47, 0xd2, 0x6a, 0xa6, 0x17, 0x7e, 0x09, 0x8c, 0xd2,
	0xee, 0xac, 0x75, 0x51, 0x99, 0xc0, 0x13, 0xb8, 0xc8, 0x3e,
};

static const uint8_t ravyn_recovery_agent_cdhash[CS_CDHASH_LEN] = {
	0xd3, 0x6b, 0x5f, 0x9a, 0xc8, 0xe8, 0x22, 0xeb, 0x65, 0x5a,
	0x34, 0x3e, 0xa2, 0x84, 0xe3, 0x34, 0x24, 0x80, 0xce, 0x8d,
};

enum {
	RAVYN_RECOVERY_BOOT_PICKER = 0,
	RAVYN_RECOVERY_KEY_ASSISTANT = 2,
};

/* Original Boot Picker, Springboard, KeyRecoveryAssistant, Installer Progress.
 * Manifest-pinned Recovery cache records999/225/212/660. */
static const uint8_t ravyn_recovery_ui_cdhashes[][CS_CDHASH_LEN] = {
	[RAVYN_RECOVERY_BOOT_PICKER] = { 0xf3, 0xa0, 0xaf, 0x17, 0xe5, 0xea, 0x99, 0xd9, 0xf0, 0x97,
	  0xee, 0xc1, 0xbd, 0xe4, 0x00, 0xd0, 0x9f, 0xc6, 0x2f, 0xa0 },
	{ 0x3d, 0x96, 0x22, 0x54, 0xb4, 0x91, 0xf6, 0x3f, 0x3b, 0x22,
	  0xf2, 0xc6, 0xd2, 0xd4, 0xc1, 0xae, 0xaf, 0xb7, 0xbb, 0xa8 },
	[RAVYN_RECOVERY_KEY_ASSISTANT] = { 0x39, 0x0b, 0x9a, 0xe9, 0x1d, 0xc5, 0x3f, 0x96, 0x13, 0xbb,
	  0x6c, 0xe1, 0x99, 0x3f, 0x75, 0xd3, 0x13, 0x10, 0xdd, 0x92 },
	{ 0xa8, 0x00, 0xb0, 0x5e, 0x6e, 0x85, 0x69, 0x15, 0x78, 0x66,
	  0x64, 0x0e, 0x72, 0x17, 0x7e, 0x15, 0xd3, 0x13, 0x64, 0x3d },
	{ 0xe8, 0x7b, 0xc6, 0xe8, 0x39, 0x4e, 0x20, 0x21, 0xd5, 0x6b,
	  0xb0, 0xe0, 0xd6, 0x83, 0xf4, 0x2e, 0x4a, 0x41, 0x4e, 0xff },
};

/* Original diskarbitrationd: manifest record535, all42 code pages verified. */
static const uint8_t ravyn_diskarbitrationd_cdhash[CS_CDHASH_LEN] = {
    0x89, 0xfb, 0xb7, 0x51, 0xbb, 0x69, 0xbf, 0xef, 0x02, 0x2a,
    0xfd, 0xc8, 0xdb, 0xa1, 0xc7, 0xeb, 0xcf, 0xe5, 0xfc, 0xa7,
};

/* Original storagekitd, Recovery trust cache record 985. */
static const uint8_t ravyn_storagekitd_cdhash[CS_CDHASH_LEN] = {
	0xf0, 0x3d, 0x12, 0x7d, 0xc9, 0x30, 0x93, 0xa1, 0xc0, 0x62,
	0xe5, 0x05, 0x9c, 0x24, 0x30, 0x15, 0x45, 0x37, 0xd2, 0x64,
};

static const uint8_t ravyn_diskmanagementd_cdhash[CS_CDHASH_LEN] = {
	0xdb, 0x7f, 0xea, 0xb8, 0xbe, 0x22, 0x66, 0x8d, 0x7d, 0x71,
	0x3e, 0xac, 0x18, 0x88, 0x3e, 0xf4, 0xcd, 0xfa, 0x72, 0x50,
};

static const uint8_t ravyn_diskutil_cdhash[CS_CDHASH_LEN] = {
	0xed, 0x97, 0xa0, 0x7f, 0x8b, 0x29, 0x1d, 0xa6, 0xfa, 0x4f,
	0xae, 0xdb, 0x73, 0xe7, 0xd6, 0x35, 0x7b, 0x6c, 0x47, 0x9d,
};

static const uint8_t ravyn_osinstallersetupd_cdhash[CS_CDHASH_LEN] = {
	0xaf, 0x5a, 0x9d, 0xed, 0x4c, 0x5e, 0xc1, 0x0f, 0x97, 0x54,
	0xd2, 0x1d, 0xf8, 0x74, 0x69, 0xf7, 0x65, 0x5a, 0xf5, 0xa5,
};

static const uint8_t ravyn_newfs_apfs_cdhash[CS_CDHASH_LEN] = {
	0x7e, 0x84, 0xc2, 0x87, 0xc1, 0x37, 0x78, 0x03, 0xf1, 0x31,
	0xc5, 0xca, 0x23, 0x04, 0xa9, 0xf7, 0xbc, 0xa7, 0x45, 0x76,
};

static const uint8_t ravyn_apfs_util_cdhash[CS_CDHASH_LEN] = {
	0x71, 0x7e, 0xeb, 0xad, 0xae, 0x36, 0x3d, 0x77, 0x80, 0x87,
	0x74, 0xb8, 0x88, 0x67, 0x63, 0x26, 0x84, 0x14, 0xa7, 0x39,
};

static const uint8_t ravyn_authd_cdhash[CS_CDHASH_LEN] = {
	0x53, 0x3b, 0xbf, 0xa6, 0x01, 0x36, 0x9e, 0x0e, 0x9c, 0x4c,
	0x83, 0x42, 0xe6, 0x30, 0x80, 0x80, 0x61, 0x6e, 0x2b, 0x85,
};

static const uint8_t ravyn_securityd_cdhash[CS_CDHASH_LEN] = {
	0x0b, 0x08, 0x37, 0x10, 0xf4, 0x97, 0x04, 0x09, 0x53, 0x0f,
	0xfd, 0x1a, 0x2b, 0xbc, 0x29, 0xd0, 0x55, 0x71, 0x8d, 0xef,
};

static const uint8_t ravyn_distnoted_cdhash[CS_CDHASH_LEN] = {
	0xa3, 0xb0, 0x7c, 0xfa, 0x6f, 0xc4, 0x9d, 0x69, 0x66, 0x1d,
	0x85, 0xef, 0xbd, 0xcb, 0x42, 0x99, 0x6d, 0x42, 0xfb, 0x16,
};

static const uint8_t ravyn_mount_apfs_cdhash[CS_CDHASH_LEN] = {
	0x33, 0xca, 0x98, 0xcb, 0x72, 0x71, 0x88, 0x35, 0xe8, 0x78,
	0x11, 0x29, 0xf3, 0x0c, 0x9c, 0x70, 0xdb, 0x24, 0x60, 0x32,
};

static const uint8_t ravyn_fsck_apfs_cdhash[CS_CDHASH_LEN] = {
	0xb2, 0x41, 0x8e, 0x31, 0xfe, 0x62, 0x88, 0x2e, 0xff, 0x3e,
	0x78, 0xe4, 0xa1, 0xef, 0x35, 0xef, 0xec, 0xe4, 0xad, 0x3a,
};

static const uint8_t ravyn_bless_cdhash[CS_CDHASH_LEN] = {
	0x4b, 0x42, 0xc8, 0xbc, 0x52, 0xff, 0x1e, 0x0f, 0xe0, 0x14,
	0xf7, 0xb8, 0x86, 0x94, 0x00, 0x63, 0x66, 0x60, 0x89, 0x6e,
};

static const uint8_t ravyn_mount_cdhash[CS_CDHASH_LEN] = {
	0x82, 0xa7, 0x20, 0xf5, 0x82, 0x65, 0x5e, 0x0b, 0x68, 0x57,
	0xb3, 0xe8, 0x72, 0x1b, 0xdb, 0x31, 0x0b, 0x9a, 0xd5, 0xf1,
};

static const uint8_t ravyn_configd_cdhash[CS_CDHASH_LEN] = {
	0x4e, 0x5a, 0xc2, 0xa6, 0x70, 0x58, 0x35, 0x7d, 0x2a, 0x1a,
	0x8d, 0xbd, 0xdf, 0x23, 0x82, 0x4e, 0x05, 0x3e, 0x1b, 0x82,
};

static const uint8_t ravyn_recoveryosd_cdhash[CS_CDHASH_LEN] = {
	0x18, 0xfa, 0x5b, 0x65, 0x86, 0xf5, 0xe0, 0xd2, 0x29, 0x4e,
	0xda, 0xfd, 0xf7, 0xb8, 0x44, 0xc1, 0x19, 0x5c, 0x2a, 0x8a,
};

static const uint8_t ravyn_pointer_probe_cdhash[CS_CDHASH_LEN] = {
	0x1f, 0xb3, 0x3b, 0xce, 0x9d, 0xee, 0xda, 0x3e, 0x51, 0x7d,
	0x7c, 0xaa, 0xca, 0x6c, 0xa6, 0xc2, 0x27, 0xf0, 0x69, 0xee,
};

static bool
ravyn_recovery_trusted(vnode_t vp, struct cs_blob *blob, const char *boot_arg,
    const uint8_t cdhash[CS_CDHASH_LEN])
{
	int enabled = 0;
	if (!vp || !blob ||
	    !PE_parse_boot_argn(boot_arg, &enabled, sizeof(enabled)) ||
	    enabled != 1 || !ravyn_recovery_hfs_enabled() ||
	    csblob_get_hashtype(blob) != CS_HASHTYPE_SHA256 ||
	    memcmp(csblob_get_cdhash(blob), cdhash, CS_CDHASH_LEN) != 0) {
		return false;
	}

	mount_t mount = vnode_mount(vp);
	if (!mount || !vnode_isreg(vp)) {
		return false;
	}
	const struct vfsstatfs *stats = vfs_statfs(mount);
	return ((vfs_flags(mount) & MNT_ROOTFS) != 0 && vfs_isrdonly(mount) &&
	    strcmp(stats->f_fstypename, "hfs") == 0 &&
	    strcmp(stats->f_mntfromname, "/dev/md0") == 0) ||
	    (strcmp(stats->f_mntfromname, "/dev/md1") == 0);
}

static bool
ravyn_recovery_ui_trusted(vnode_t vp, struct cs_blob *blob)
{
	for (unsigned int i = 0; i < sizeof(ravyn_recovery_ui_cdhashes) /
	    sizeof(ravyn_recovery_ui_cdhashes[0]); i++) {
		if (ravyn_recovery_trusted(vp, blob, "ravyn_recovery_ui_lookup",
		    ravyn_recovery_ui_cdhashes[i])) {
			return true;
		}
	}
	return false;
}

static int
ravyn_recovery_check_signature(vnode_t vp, struct label *label __unused,
    cpu_type_t cpu_type, struct cs_blob *blob, unsigned int *cs_flags,
    unsigned int *signer_type __unused, int flags __unused,
    char **failure __unused, size_t *failure_len __unused)
{
	/* File-descriptor signature attachment calls this hook with CPU_TYPE_ANY. */
	if ((cpu_type != CPU_TYPE_ARM64 && cpu_type != CPU_TYPE_ANY) ||
	    (*cs_flags & CS_VALID) == 0) {
		return 0;
	}
	/*
	 * dyld accepts macOS arm64e dylibs only when their attached signature
	 * is platform code. This exact Apple OS library is record 1034 of the
	 * manifest-pinned Recovery trust cache; all 13 code pages and its
	 * requirements slot were verified before pinning the CodeDirectory.
	 * Keep the ordinary VM code-page checks and restrict this to md0.
	 */
	if (ravyn_recovery_trusted(vp, blob, "ravyn_recovery_objc_trust",
	    ravyn_objc_trampolines_cdhash)) {
		*cs_flags |= CS_SIGNED | CS_HARD | CS_PLATFORM_BINARY;
		printf("RAVYN-RECOVERY-TRUST: matched platform %s on the read-only Recovery root\n",
		    csblob_get_identity(blob));
	}
	if (ravyn_recovery_trusted(vp, blob, "ravyn_recovery_windowserver_trust", ravyn_windowserver_cdhash) ||
	    ravyn_recovery_trusted(vp, blob, "ravyn_recovery_security_lookup", ravyn_recoveryosd_cdhash) ||
	    ravyn_recovery_trusted(vp, blob, "ravyn_recovery_console_lookup", ravyn_configd_cdhash) ||
	    ravyn_recovery_trusted(vp, blob, "ravyn_recovery_agent_lookup", ravyn_recovery_agent_cdhash) ||
	    ravyn_recovery_ui_trusted(vp, blob) ||
	    ravyn_recovery_trusted(vp, blob, "ravyn_recovery_ui_lookup", ravyn_pointer_probe_cdhash) ||
	    ravyn_recovery_trusted(vp, blob, "ravyn_recovery_storage_lookup", ravyn_diskarbitrationd_cdhash) ||
	    ravyn_recovery_trusted(vp, blob, "ravyn_recovery_storage_lookup", ravyn_storagekitd_cdhash) ||
	    ravyn_recovery_trusted(vp, blob, "ravyn_recovery_storage_lookup", ravyn_diskmanagementd_cdhash) ||
	    ravyn_recovery_trusted(vp, blob, "ravyn_recovery_storage_lookup", ravyn_diskutil_cdhash) ||
	    ravyn_recovery_trusted(vp, blob, "ravyn_recovery_storage_lookup", ravyn_osinstallersetupd_cdhash) ||
	    ravyn_recovery_trusted(vp, blob, "ravyn_recovery_storage_lookup", ravyn_newfs_apfs_cdhash) ||
	    ravyn_recovery_trusted(vp, blob, "ravyn_recovery_storage_lookup", ravyn_apfs_util_cdhash) ||
	    ravyn_recovery_trusted(vp, blob, "ravyn_recovery_security_lookup", ravyn_authd_cdhash) ||
	    ravyn_recovery_trusted(vp, blob, "ravyn_recovery_security_lookup", ravyn_securityd_cdhash) ||
	    ravyn_recovery_trusted(vp, blob, "ravyn_recovery_notify_lookup", ravyn_distnoted_cdhash) ||
	    ravyn_recovery_trusted(vp, blob, "ravyn_recovery_storage_lookup", ravyn_mount_apfs_cdhash) ||
	    ravyn_recovery_trusted(vp, blob, "ravyn_recovery_storage_lookup", ravyn_fsck_apfs_cdhash) ||
	    ravyn_recovery_trusted(vp, blob, "ravyn_recovery_storage_lookup", ravyn_bless_cdhash) ||
	    ravyn_recovery_trusted(vp, blob, "ravyn_recovery_storage_lookup", ravyn_mount_cdhash) ||
	    ravyn_recovery_trusted(vp, blob, "ravyn_recovery_storage_lookup", ravyn_mount_apfs_cdhash) ||
	    ravyn_recovery_trusted(vp, blob, "ravyn_recovery_storage_lookup", ravyn_fsck_apfs_cdhash) ||
	    ravyn_recovery_trusted(vp, blob, "ravyn_recovery_storage_lookup", ravyn_bless_cdhash) ||
	    ravyn_recovery_trusted(vp, blob, "ravyn_recovery_storage_lookup", ravyn_mount_cdhash)) {
		/* Retain VM page validation and the entitlement special-slot check. */
		*cs_flags |= CS_SIGNED | CS_HARD | CS_PLATFORM_BINARY;
		printf("RAVYN-RECOVERY-TRUST: matched %s on the read-only Recovery root\n",
		    csblob_get_identity(blob));
	}
	return 0;
}

/*
 * A null operation asks whether a process has a Sandbox profile. This
 * compatibility policy has no per-process label slot and cannot install
 * profiles. Report that actual state after checking the live audit generation.
 */
static int
ravyn_recovery_sandbox_presence(const struct ravyn_rootless_query *query)
{
	if (!ravyn_recovery_hfs_enabled()) {
		return ENOPOLICY;
	}
	printf("RAVYN-SANDBOX-PRESENCE pid=%llu filter=%#llx flags=%#llx generation=%#llx\n",
	    query->pid, query->filter, query->flags, query->reserved[0]);
	bool audit = query->flags == RAVYN_AUDIT_QUERY_FLAGS;
	bool self = query->flags == 0 && query->pid == (uint64_t)proc_selfpid() &&
	    query->reserved[0] == 0;
	if (query->pid == 0 || query->pid > INT_MAX || query->filter != 0 ||
	    query->fd != 0 || (!audit && !self) ||
	    (audit && (query->reserved[0] == 0 || query->reserved[0] > UINT32_MAX))) {
		return EINVAL;
	}
	for (unsigned int i = 1; i < sizeof(query->reserved) / sizeof(query->reserved[0]); i++) {
		if (query->reserved[i] != 0) {
			return EINVAL;
		}
	}
	proc_t subject = proc_find((int)query->pid);
	if (subject == PROC_NULL) {
		return ESRCH;
	}
	proc_lock(subject);
	bool valid = audit ? (uint32_t)proc_pidversion(subject) == (uint32_t)query->reserved[0] :
	    subject == current_proc();
	proc_unlock(subject);
	proc_rele(subject);
	if (!valid) {
		return ESRCH;
	}
	uint64_t sandboxed = 0;
	return copyout(&sandboxed, (user_addr_t)query->result, sizeof(sandboxed));
}

/*
 * Existing root clients and the exact signed Recovery WindowServer may ask
 * read-only Data-volume questions. UID88 alone is insufficient; preserve the
 * pinned executable, current credentials, text-vnode identity and CS flags.
 */
static bool
ravyn_recovery_read_client(struct proc *p, kauth_cred_t cred)
{
    if (p != current_proc() || cred != kauth_cred_get()) {
        return false;
    }
    if (kauth_cred_issuser(cred)) {
        return true;
    }
    if (!ravyn_recovery_preferences_enabled() || kauth_cred_getuid(cred) != 88) {
        return false;
    }
    vnode_t vp = proc_getexecutablevnode(p);
    if (vp == NULL) {
        return false;
    }
    off_t offset = proc_getexecutableoffset(p);
    struct cs_blob *blob = csvnode_get_blob(vp, offset);
    bool trusted = ravyn_recovery_trusted(vp, blob,
        "ravyn_recovery_windowserver_trust", ravyn_windowserver_cdhash);
    if (trusted) {
        unsigned int required = CS_SIGNED | CS_HARD | CS_VALID;
        proc_lock(p);
        trusted = p->p_textvp == vp && p->p_textoff == offset &&
            p->p_ucred == cred && (p->p_csflags & required) == required;
        proc_unlock(p);
    }
    vnode_put(vp);
    return trusted;
}

static bool
ravyn_recovery_storage_caller_trusted(vnode_t vp, struct cs_blob *blob)
{
	return ravyn_recovery_trusted(vp, blob, "ravyn_recovery_storage_lookup", ravyn_storagekitd_cdhash) ||
	    ravyn_recovery_trusted(vp, blob, "ravyn_recovery_storage_lookup", ravyn_diskmanagementd_cdhash) ||
	    ravyn_recovery_trusted(vp, blob, "ravyn_recovery_storage_lookup", ravyn_diskutil_cdhash) ||
	    ravyn_recovery_trusted(vp, blob, "ravyn_recovery_storage_lookup", ravyn_osinstallersetupd_cdhash) ||
	    ravyn_recovery_trusted(vp, blob, "ravyn_recovery_security_lookup", ravyn_authd_cdhash) ||
	    ravyn_recovery_trusted(vp, blob, "ravyn_recovery_security_lookup", ravyn_securityd_cdhash) ||
	    ravyn_recovery_trusted(vp, blob, "ravyn_recovery_notify_lookup", ravyn_distnoted_cdhash) ||
	    ravyn_recovery_trusted(vp, blob, "ravyn_recovery_storage_lookup", ravyn_mount_apfs_cdhash) ||
	    ravyn_recovery_trusted(vp, blob, "ravyn_recovery_storage_lookup", ravyn_fsck_apfs_cdhash) ||
	    ravyn_recovery_trusted(vp, blob, "ravyn_recovery_storage_lookup", ravyn_bless_cdhash) ||
	    ravyn_recovery_trusted(vp, blob, "ravyn_recovery_storage_lookup", ravyn_mount_cdhash) ||
	    ravyn_recovery_ui_trusted(vp, blob) ||
	    ravyn_recovery_trusted(vp, blob, "ravyn_recovery_ui_lookup", ravyn_pointer_probe_cdhash);
}

/* Launchd still owns and resolves the Mach right. This answers its access query. */
static int
ravyn_recovery_service_access(struct proc *p, const struct ravyn_rootless_query *query,
    bool registration)
{
	if (!ravyn_recovery_hfs_enabled() || p != initproc || p != current_proc() ||
	    !kauth_cred_issuser(kauth_cred_get())) {
		return ENOPOLICY;
	}
	int enabled = 0;
	if (!PE_parse_boot_argn("ravyn_recovery_security_lookup", &enabled, sizeof(enabled)) ||
	    enabled != 1) {
		return ENOPOLICY;
	}

	char service[128];
	size_t copied = 0;
	int error = copyinstr((user_addr_t)query->fd, service, sizeof(service), &copied);
	if (error != 0) {
		return error;
	}
	if (registration && strcmp(service, "com.apple.tsm.portname") != 0 &&
	    strcmp(service, "com.apple.axserver") != 0) {
		return ENOPOLICY;
	}
	/*
	 * Big Sur WindowServer looks up its own registered CA endpoint using the
	 * PID form of sandbox_check, not the audit-token form. Only launchd may
	 * broker this narrowly opted-in query; the live executable/credential
	 * checks below determine the subject, not any user-supplied identity.
	 */
	const bool render = !registration && strcmp(service, "com.apple.CARenderServer") == 0;
	if (query->flags != RAVYN_AUDIT_QUERY_FLAGS && !(render && query->flags == 0)) {
		return ENOPOLICY;
	}
	const bool audited = query->flags == RAVYN_AUDIT_QUERY_FLAGS;
	const bool notification = strcmp(service, "com.apple.system.notification_center") == 0;
	const bool windowserver = notification || render;
	const bool launchservices = strcmp(service, "com.apple.coreservices.launchservicesd") == 0;
	const bool configuration = strcmp(service, "com.apple.SystemConfiguration.configd") == 0;
	const bool recovery_agent = strcmp(service, "com.apple.recoveryos_agent") == 0;
	const bool installer_progress = strcmp(service, "com.apple.InstallerProgress") == 0;
	const bool storagekit_endpoint = strcmp(service, "com.apple.storagekitd") == 0;
	const bool storage_endpoint = storagekit_endpoint ||
	    strcmp(service, "com.apple.DiskArbitration.diskarbitrationd") == 0;
	const bool diskmanagement_endpoint = strcmp(service, "com.apple.diskmanagementd") == 0;
	const bool xpc_name = query->filter == RAVYN_RECOVERY_XPC_NAME_FILTER;
	const bool authorization_endpoint = xpc_name && strcmp(service, "com.apple.authd") == 0;
	if (xpc_name && !authorization_endpoint) {
		return ENOPOLICY;
	}
	if (storage_endpoint || diskmanagement_endpoint || authorization_endpoint) {
		int storage = 0;
		if (!PE_parse_boot_argn("ravyn_recovery_storage_lookup", &storage, sizeof(storage)) || storage != 1) {
			return ENOPOLICY;
		}
	}
	const bool launchservices_database = strcmp(service, "com.apple.lsd.mapdb") == 0 ||
	    strcmp(service, "com.apple.lsd.modifydb") == 0;
	const bool graphics_service = strcmp(service, "com.apple.windowserver") == 0 ||
	    strcmp(service, "com.apple.windowserver.active") == 0;
	const bool font_endpoint = strcmp(service, "com.apple.fonts") == 0;
	if (font_endpoint) {
		int fonts = 0;
		if (!PE_parse_boot_argn("ravyn_recovery_font_lookup", &fonts, sizeof(fonts)) || fonts != 1) {
			return ENOPOLICY;
		}
	}
	const bool ui_endpoint = installer_progress || launchservices_database ||
	    storage_endpoint || font_endpoint;
	if (registration || launchservices || ui_endpoint) {
		int agent = 0, ui = 0;
		(void)PE_parse_boot_argn("ravyn_recovery_agent_lookup", &agent, sizeof(agent));
		(void)PE_parse_boot_argn("ravyn_recovery_ui_lookup", &ui, sizeof(ui));
		if ((ui_endpoint && ui != 1) || (agent != 1 && ui != 1)) {
			return ENOPOLICY;
		}
	} else if (render) {
		int render_enabled = 0;
		if (!PE_parse_boot_argn("ravyn_recovery_render_lookup", &render_enabled, sizeof(render_enabled)) ||
		    render_enabled != 1) {
			return ENOPOLICY;
		}
	} else if (notification) {
		int notify_enabled = 0;
		if (!PE_parse_boot_argn("ravyn_recovery_notify_lookup", &notify_enabled, sizeof(notify_enabled)) ||
		    notify_enabled != 1) {
			return ENOPOLICY;
		}
	} else if (configuration) {
		int console = 0;
		if (!PE_parse_boot_argn("ravyn_recovery_console_lookup", &console, sizeof(console)) ||
		    console != 1) {
			return ENOPOLICY;
		}
	} else if (recovery_agent) {
		int agent = 0;
		if (!PE_parse_boot_argn("ravyn_recovery_agent_lookup", &agent, sizeof(agent)) ||
		    agent != 1) {
			return ENOPOLICY;
		}
	} else if (!diskmanagement_endpoint && !authorization_endpoint &&
	    strcmp(service, "com.apple.SecurityServer") != 0) {
		int graphics = 0;
		if (!graphics_service ||
		    !PE_parse_boot_argn("ravyn_recovery_graphics_lookup", &graphics, sizeof(graphics)) ||
		    graphics != 1) {
			return ENOPOLICY;
		}
	}
	if (query->pid == 0 || query->pid > INT_MAX ||
	    (audited && (query->reserved[0] == 0 || query->reserved[0] > UINT32_MAX))) {
		return EINVAL;
	}
	for (unsigned int i = audited ? 1 : 0; i < sizeof(query->reserved) / sizeof(query->reserved[0]); i++) {
		if (query->reserved[i] != 0) {
			return ENOPOLICY;
		}
	}

	proc_t subject = proc_find((int)query->pid);
	if (subject == PROC_NULL) {
		return ESRCH;
	}
	uint64_t denied = 1;
	vnode_t vp = proc_getexecutablevnode(subject);
	if (vp != NULL) {
		off_t offset = proc_getexecutableoffset(subject);
		struct cs_blob *blob = csvnode_get_blob(vp, offset);
		const uint8_t *cdhash = registration ? ravyn_recovery_agent_cdhash :
		    (windowserver ? ravyn_windowserver_cdhash : ravyn_recoveryosd_cdhash);
		const char *trust_arg = registration ? "ravyn_recovery_agent_lookup" :
		    (windowserver ? "ravyn_recovery_windowserver_trust" : "ravyn_recovery_security_lookup");
		bool trusted = ravyn_recovery_trusted(vp, blob, trust_arg, cdhash);
		if (diskmanagement_endpoint || authorization_endpoint) {
			trusted = ravyn_recovery_storage_caller_trusted(vp, blob);
		} else if (storagekit_endpoint || storage_endpoint) {
			trusted = ravyn_recovery_storage_caller_trusted(vp, blob) ||
			    ravyn_recovery_trusted(vp, blob, "ravyn_recovery_storage_lookup", ravyn_diskarbitrationd_cdhash);
		} else if (ui_endpoint) {
			trusted = ravyn_recovery_ui_trusted(vp, blob);
		}
		if (registration && !trusted) {
			trusted = ravyn_recovery_ui_trusted(vp, blob);
		}
		/* The storage daemon needs real configd/VFS notifications to start.
		 * Its exact identity is independently pinned; a process name grants nothing. */
		const bool storage_subject = (configuration || notification) &&
		    ravyn_recovery_trusted(vp, blob, "ravyn_recovery_storage_lookup", ravyn_diskarbitrationd_cdhash);
		if (storage_subject) {
			trusted = true;
		}
		if (configuration && !trusted) {
			trusted = ravyn_recovery_trusted(vp, blob, "ravyn_recovery_console_lookup", ravyn_configd_cdhash);
		}
		if (!registration && (graphics_service || launchservices ||
		    strcmp(service, "com.apple.SecurityServer") == 0) && !trusted) {
			trusted = ravyn_recovery_trusted(vp, blob, "ravyn_recovery_agent_lookup",
			    ravyn_recovery_agent_cdhash) ||
			    ravyn_recovery_storage_caller_trusted(vp, blob);
		}
		if (!registration && (graphics_service || launchservices || recovery_agent) && !trusted) {
			trusted = ravyn_recovery_ui_trusted(vp, blob);
		}
		if (trusted) {
			const unsigned int required = CS_SIGNED | CS_HARD | CS_VALID;
			kauth_cred_t cred = kauth_cred_proc_ref(subject);
			proc_lock(subject);
			if (subject->p_textvp == vp && subject->p_textoff == offset &&
			    (!audited || (uint32_t)proc_pidversion(subject) == (uint32_t)query->reserved[0]) &&
			    (subject->p_csflags & required) == required &&
			    subject->p_ucred == cred &&
			    (windowserver && !storage_subject ? kauth_cred_getuid(cred) == 88 : kauth_cred_issuser(cred))) {
				denied = 0;
			}
			proc_unlock(subject);
			kauth_cred_unref(&cred);
		}
		vnode_put(vp);
	}
	proc_rele(subject);
#if DEBUG || DEVELOPMENT
	if (denied == 0) {
		printf("RAVYN-RECOVERY-LOOKUP: allow %s%s for pinned executable PID %llu\n",
		    registration ? "local registration " : "", service, query->pid);
	}
#endif
	return copyout(&denied, (user_addr_t)query->result, sizeof(denied));
}

static int
ravyn_recovery_grant_privilege(kauth_cred_t cred, int privilege)
{
	if (privilege != PRIV_WORK_INTERVAL || cred != kauth_cred_get()) {
		return EPERM;
	}
	proc_t p = current_proc();
	const unsigned int required = CS_SIGNED | CS_HARD | CS_VALID;
	if (!p || (p->p_csflags & required) != required ||
	    !ravyn_recovery_trusted(p->p_textvp, csproc_get_blob(p),
	    "ravyn_recovery_windowserver_trust", ravyn_windowserver_cdhash)) {
		return EPERM;
	}
	return IOTaskHasEntitlement(current_task(), "com.apple.private.kernel.work-interval") ? 0 : EPERM;
}
#endif

static SECURITY_READ_ONLY_EARLY(struct mac_policy_ops) ravyn_rootless_ops = {
#if defined(__arm64__) && defined(ARM64_BOARD_CONFIG_BCM2837)
	.mpo_vnode_check_signature = ravyn_recovery_check_signature,
	.mpo_priv_grant = ravyn_recovery_grant_privilege,
#endif
	.mpo_policy_syscall = ravyn_rootless_policy_syscall,
	.mpo_file_check_mmap = ravyn_file_check_mmap,
	.mpo_vnode_check_create = ravyn_vnode_check_create,
	.mpo_vnode_check_clone = ravyn_vnode_check_clone,
	.mpo_vnode_check_deleteextattr = ravyn_vnode_check_deleteextattr,
	.mpo_vnode_check_exchangedata = ravyn_vnode_check_exchangedata,
	.mpo_vnode_check_link = ravyn_vnode_check_namespace,
	.mpo_vnode_check_open = ravyn_vnode_check_open,
	.mpo_vnode_check_rename = ravyn_vnode_check_rename,
	.mpo_vnode_check_setacl = ravyn_vnode_check_setacl,
	.mpo_vnode_check_setattrlist = ravyn_vnode_check_setattrlist,
	.mpo_vnode_check_setextattr = ravyn_vnode_check_setextattr,
	.mpo_vnode_check_setflags = ravyn_vnode_check_setflags,
	.mpo_vnode_check_setmode = ravyn_vnode_check_setmode,
	.mpo_vnode_check_setowner = ravyn_vnode_check_setowner,
	.mpo_vnode_check_setutimes = ravyn_vnode_check_setutimes,
	.mpo_vnode_check_truncate = ravyn_vnode_check_write,
	.mpo_vnode_check_unlink = ravyn_vnode_check_namespace,
	.mpo_vnode_check_uipc_bind = ravyn_vnode_check_create,
	.mpo_vnode_check_write = ravyn_vnode_check_write,
};

static SECURITY_READ_ONLY_LATE(struct mac_policy_conf) ravyn_rootless_conf = {
	.mpc_name = "Sandbox",
	.mpc_fullname = "RavynOS restricted-file and root process-info compatibility",
	.mpc_field_off = NULL,
	.mpc_labelnames = NULL,
	.mpc_labelname_count = 0,
	.mpc_ops = &ravyn_rootless_ops,
	.mpc_loadtime_flags = 0,
	.mpc_runtime_flags = 0,
};

static SECURITY_READ_ONLY_LATE(mac_policy_handle_t) ravyn_rootless_handle;

void
ravyn_rootless_compat_init(void)
{
	int enabled = 0;
	int error;

	if (!PE_parse_boot_argn("ravyn_rootless_compat", &enabled, sizeof(enabled)) ||
	    enabled != 1) {
		return;
	}
	error = mac_policy_register(&ravyn_rootless_conf, &ravyn_rootless_handle, NULL);
	if (error != 0) {
		printf("ravyn_rootless_compat: Sandbox policy registration failed (%d)\n", error);
		return;
	}
#if defined(__arm64__) && defined(ARM64_BOARD_CONFIG_BCM2837)
	if (ravyn_recovery_hfs_enabled()) {
		ravyn_recovery_sandbox_sentinel_init();
	}
#endif
	printf("ravyn_rootless_compat: registered Sandbox restricted-file and root process-info compatibility policy\n");
}

#endif /* CONFIG_MACF */
