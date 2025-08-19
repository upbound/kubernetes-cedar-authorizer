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

## Kubernetes Conditional Authorization

The idea is to extend Kubernetes Authorization framework with conditions on the
request payload and/or stored object, in order for the request to succeed.

For example:

- TODO

Conditional Authorization is available IFF:

- The SubjectAccessReview (SAR) sender indicates it supports the feature using the
  `kubernetes.io/ConditionalAuthorizationFeature=true` annotation. Conditions
  MUST NOT be returned if this annotation is not set, but instead any
  conditional response that was yielded must be folded into a `NoOpinion`
  response.
  - This allows for backwards-compability with an old SAR sender, but new SAR
    authorizer implementation.
- The SubjectAccessReview server support conditions, and when needed, responds
  with `.status.conditions` non-null, along with `.status.allowed=false` and
  `.status.denied=false`.
  - In case the SAR sender is new, but SAR authorizer implementation old, no
    conditions will ever be returned, but all existing properties about the
    other authorizer are backwards-compatible.
- The `apiGroup != *`, `resource != *`,
  `subresource == "" || (subresource != "" && subresource != "*")`, and verb is
  one of `create`, `update`, `patch`, `delete`. If conditions are present in
  these conditions, then the API server makes sure that the conditions are
  type-safe according to the current OpenAPI schema of the targeted resource.




TODO: When the API server encounters a conditional response, but has multiple
other authorizers left in the chain, should they be consulted, or should it just
short-circuit? I guess just short-circuit, as a conditional response != NoOpinion,
there is clearly an opinion about this request by this authorizer.



[Cedar]: https://github.com/cedar-policy/cedar
[Kubernetes]: https://github.com/kubernetes/kubernetes
[MSc thesis]: https://github.com/luxas/research/blob/main/msc_thesis.pdf
[Cedar Access Control for Kubernetes]: github.com/cedar-policy/cedar-access-control-for-k8s
[Typed Partial Evaluation feature]: https://github.com/cedar-policy/rfcs/blob/main/text/0095-type-aware-partial-evaluation.md
[thesis-presentation]: https://speakerdeck.com/luxas/usable-access-control-in-cloud-management-systems
[SIG Auth meeting]: https://youtu.be/Clg-rz9qlUA