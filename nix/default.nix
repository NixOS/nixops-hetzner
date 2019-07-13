{
  config_exporters = { optionalAttrs, ... }: [
    (config: { hetzner = optionalAttrs (config.deployment.targetEnv == "hetzner") config.deployment.hetzner; })
  ];
  options = [
    ./hetzner.nix
  ];
  resources = { evalResources, zipAttrs, resourcesByType, ... }: { };
}
