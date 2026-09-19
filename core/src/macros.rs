#[macro_export]
macro_rules! exploit {
    ($exploit:ty, $proto:expr, $port:expr, $da:expr) => {{
        #[cfg(feature = "exploits")]
        {
            if !$proto.patched {
                // Derive a short, human readable name for the exploit type
                // (e.g. `penumbra::exploit::linecode::Linecode` -> `Linecode`).
                let name: &'static str = std::any::type_name::<$exploit>();
                let short: &'static str = name.rsplit("::").next().unwrap_or(name);

                log::info!("[Exploit] Checking {short}...");
                let mut exploit = <$exploit>::default();

                match <$exploit as $crate::exploit::Exploit<Self, P>>::run(
                    &mut exploit,
                    $proto,
                    $port,
                    $da,
                ) {
                    Ok(true) => {
                        log::info!("[Exploit] {short} succeeded - DA patched, extensions loaded");
                        $proto.patched = true;
                    }
                    Ok(false) => {
                        log::debug!("[Exploit] {short} not applicable on this device");
                    }
                    Err(e) => {
                        log::debug!("[Exploit] {short} failed: {e}");
                    }
                }
            }
        }
    }};
}
