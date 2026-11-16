# Explicit Monterey Sandbox link binding

The optional leading plktool argument --monterey-sandbox-v80 adapts only the exact x86_64 Sandbox donor with SHA256 1a8465056f12799d6de02a5f42836d62411e4bf9edcfc654799fa5a45184f2c1. It rejects a different Sandbox executable, a repeated Sandbox link, or a cache without exactly one successful adapted link. Bundle identity alone never selects a MAC ABI.

For that one link, the prelinker privately clones its unique direct com.apple.kpi.dsep dependency interface. It requires exactly one undefined external _mac_policy_register symbol, changes only the clone to an N_INDR external alias targeting the real kernel _mac_policy_register_v80, extends its string table and sectionless LINKEDIT sizes, and derives a private-interface UUID. The caller releases the private buffer after kxld_link_file completes on success or failure. Shared interface objects, other links and all donor executable/signature/plist bytes remain unchanged. The prelinker reports the pinned SHA, alias, private interface SHA256 and size. The known modern donor is rejected without the explicit option, preventing accidental legacy dispatch.

This uses KXLD's existing interface alias exporter, rather than changing runtime MAC registration, guessing policy names, or globally redirecting the legacy API. No modern donor is admitted by default. The kernel must actually implement the target symbol and all dependencies; this option does not supply missing semantics.

Host tests compile tests/monterey_policy_alias_test.c with -lcrypto and optionally -fsanitize=undefined. Arguments are the existing dsep pseudo interface, exact raw Monterey donor, and raw Catalina Sandbox executable. The unit cases check immutable inputs, alias bytes and bounds, donor mismatch and malformed/ambiguous interfaces.

UNVERIFIED integration gate: Before native use, prelink the exact donor with this explicit option and inspect its linked registration stub/pointer against the actual kernel _mac_policy_register_v80 address. Independently verify unchanged Catalina registration resolves to _mac_policy_register. Host unit tests are not proof that the linked cache invokes either function. Native Monterey initialization and Catalina regressions remain required.


## Explicit Monterey EndpointSecurity binding

A second leading plktool option, --monterey-endpointsecurity-v80, adapts only the x86_64 EndpointSecurity executable with SHA256 9c78dbf3c1204a2b6460694e8ce0e99b3e588573c4a0cd5348828bd0a0b1a47d. It is a separate identity and link counter from Sandbox. The prelinker rejects this Monterey executable without the explicit option, requires exactly one successful EndpointSecurity link when selected, and clones only its unique direct com.apple.kpi.dsep interface. The driver-preparation script also requires the exact Monterey Sandbox v80 profile, Apple Quarantine and the pinned Monterey EndpointSecurity bundle metadata and dependency set.

This binding maps only that module's _mac_policy_register import to the kernel's actual _mac_policy_register_v80 implementation. It does not translate or rewrite the executable's callback table; the kernel registration implementation still needs its audited v80 table translation before this driver can initialize. The exact imported endpoint profile path, linked symbol address, unchanged Catalina legacy registration and native early-client setup are required runtime gates.

Host alias tests now take five donor inputs: the dsep pseudo-interface, exact Monterey Sandbox, Catalina Sandbox, exact Monterey EndpointSecurity and Catalina EndpointSecurity executables. They validate both pinned identities and reject each corresponding non-target binary. These tests establish only the prelinker identity/alias preparation, not kernel callback compatibility or successful EndpointSecurity runtime.
