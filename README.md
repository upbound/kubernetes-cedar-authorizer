# kubernetes-cedar-authorizer

Proof of concept integrating [Cedar] with [Kubernetes], leveraging in particular
the [Typed Partial Evaluation feature] of Cedar, in order to unify Kubernetes
authorization and admission request stages. The design for this work is found in
my [MSc thesis], please read that work to understand the context. Slides from
the MSc thesis presentation are available [here][thesis-presentation].

This project is intended to be merged into
[Cedar Access Control for Kubernetes] when/if this experiment proves viable. In
addition, this project serves as a temporary playground for experimenting with
how/if Kubernetes could add support for Conditional Authorization, discussed for
example in this [SIG Auth meeting]. Hopefully, a Kubernetes Enhancement Proposal
could be written for the Conditional Authorization, given promising enough
results here and/or later in Cedar Access Control for Kubernetes.

Let me know if you have feedback or ideas.

[Cedar]: https://github.com/cedar-policy/cedar
[Kubernetes]: https://github.com/kubernetes/kubernetes
[MSc thesis]: https://github.com/luxas/research/blob/main/msc_thesis.pdf
[Cedar Access Control for Kubernetes]: github.com/cedar-policy/cedar-access-control-for-k8s
[Typed Partial Evaluation feature]: https://github.com/cedar-policy/rfcs/blob/main/text/0095-type-aware-partial-evaluation.md
[thesis-presentation]: https://speakerdeck.com/luxas/usable-access-control-in-cloud-management-systems
[SIG Auth meeting]: https://youtu.be/Clg-rz9qlUA