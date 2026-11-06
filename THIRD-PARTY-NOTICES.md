# Third-party notices

## Cloudflare security-audit skill

`skills/sast-assess/cloudflare/` is a copy of `skills/security-audit/` from
[cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill) at
commit `c1c8a8c1471069fb0e188eeaff69b8e8db6564a8`, with `SKILL.md` renamed `METHOD.md`. It is
used under the MIT licence:

> Copyright (c) 2025-2026 Cloudflare, Inc.
>
> Permission is hereby granted, free of charge, to any person obtaining a copy of this
> software and associated documentation files (the "Software"), to deal in the Software
> without restriction, including without limitation the rights to use, copy, modify, merge,
> publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
> to whom the Software is furnished to do so, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all copies or
> substantial portions of the Software.
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
> INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
> PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
> FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
> OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
> DEALINGS IN THE SOFTWARE.

The full licence text is in `skills/sast-assess/cloudflare/LICENSE`.

## GC3 AI SAST Toolkit

The run control, evidence labels, claims control, reachability proof, endpoint
authorisation map, triage, routing and reporting practices in this pack follow the
[GC3 AI SAST Toolkit](https://github.com/uk-gov-cyber/GC3-AI-SAST-Toolkit). That repository
had no licence file when it was reviewed (commit `0ec2ffe`, 21 September 2026), so no text
from it is copied here. The ideas are re-expressed in new wording, and the short label
vocabulary (for example `SAST-confirmed`, `locally-validated`, `config-dependent`) is kept so
that the outputs stay compatible with departmental processes that already use it.
