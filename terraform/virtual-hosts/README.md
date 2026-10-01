# PingFederate browser virtual hostname

This standalone Terraform state adopts PF's existing virtual-host singleton,
retains its configured names, and adds `ping.entraid.darkedges.com`. It does
**not** change PF's base URL or OAuth issuer, so the broker's existing
`PF_ISSUER=https://localhost:9031` remains valid.

Supply `PINGFEDERATE_PROVIDER_USERNAME` and
`PINGFEDERATE_PROVIDER_PASSWORD` in the Terraform process environment. Review
the plan to confirm it retains all existing names before applying:

```powershell
terraform -chdir=terraform/virtual-hosts init
terraform -chdir=terraform/virtual-hosts plan
terraform -chdir=terraform/virtual-hosts apply
```

Keep the tunnel's PF public hostname routed to the runtime port 9031, never
the admin port 9999. If the PF page still emits localhost asset links after
apply, inspect the login template's `$CurrentPingFedBaseURL` and the trusted
proxy Host header. Do not loosen PF's CSP to make cross-origin assets load.
