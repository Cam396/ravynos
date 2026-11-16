# ACPI interface experiment

Default combined provider preserves the existing ravynOS interface. Optional `ACPI_COMPONENT=platform` builds RavynACPIPlatform without its duplicate IOACPIPlatformDevice implementation or ACPI-global symbols. It derives from the genuine IOACPIPlatformExpert interface, provided at runtime by unmodified Apple IOACPIFamily1.4 from authenticated Catalina19H15 Core.pkg.

The public abstract interface header in include/apple-acpi/ is copied unchanged from Apple OSS IOACPIFamily commit cc036fa50c532d2ef738cf2a9c13f3ff00fb5b1f; APSL1.1 header retained. Public source reports1.3; it is used as an interface declaration, not relabelled as1.4. Shipped1.4 binary SHA256 b13d2438457dfbaaabcefc366546d80ad7660d46294a12df587c8897224eb88e supplies the actual implementation and advertised version.

REA/Ghidra12.1.4 procedure inventory ev_fec83a589875114f6af2279fc486eb6c08053664f247c90e0fd0bd7572bcf79c observes all32 reserved IOACPIPlatformDevice entries and its concrete API. IOACPIPlatformExpert::start analysis ev_55ed53757027513034b9e3b4421adcd7b5ed790395de758a3afec3c051fa3757 matches the public startup/global-key validation pattern. Static observations do not prove runtime behavior. Split provider retains custom configure/createNub routing explicitly through IOPlatformExpert and keeps its resource lock/one-instance guard separate from Apple global keys.

No Apple binary, dependency version or imported method is replaced with a stub. Runtime testing of the split profile remains required.
