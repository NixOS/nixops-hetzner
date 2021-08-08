# NixOps Hetzner Plugin

NixOps (formerly known as Charon) is a tool for deploying NixOS
machines in a network or cloud.

This repo contains the NixOps Hetzner Plugin.

* [Manual](https://nixos.org/nixops/manual/)
* [Installation](https://nixos.org/nixops/manual/#chap-installation) / [Hacking](https://nixos.org/nixops/manual/#chap-hacking)
* [Continuous build](http://hydra.nixos.org/jobset/nixops/master#tabs-jobs)
* [Source code](https://github.com/NixOS/nixops)
* [Issue Tracker](https://github.com/NixOS/nixops/issues)
* [Mailing list / Google group](https://groups.google.com/forum/#!forum/nixops-users)
* [Matrix - #nix:nixos.org](https://matrix.to/#/#nix:nixos.org)
* [Documentation](https://nixops.readthedocs.io/en/latest)

## Developing

To start developing on the NixOps Hetzner plugin, you can run:
```bash
  $ nix-shell -I channel:nixos-20.09 -p poetry
  $ poetry install
  $ poetry shell
```
To view active plugins:

```bash
nixops list-plugins
```
and you're ready to go.

The code should conform to style guide and types annotation standards so please make sure to run `black` and `mypy`.

## Building from source

The command to build NixOps depends on your platform.

See the main NixOps repo instructions for how to built NixOps
with this Hetzner plugin.

This document is a work in progress.
