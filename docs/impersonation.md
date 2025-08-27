# Constrained impersonation

## Background

Kubernetes API server supports impersonation, where the authenticated principal
requests to impersonate another principal. The username to impersonate must
always be specified, but also other fields (like groups, uid, extra) can be
impersonated in addition. The API server checks that the authenticated principal
has the necessary permissions to impersonate the specific fields of the UserInfo.

If the authenticated principal has the necessary permissions to impersonate all
requested userinfo fields, the authenticated principal's UserInfo is dropped, and
the request chain uses the impersonated principal's UserInfo from then on.

## Current limitations

With the API server's impersonation enforcement and SubjectAccessReview API:

- There is no way to express that e.g. "principal P can impersonate group G, but
  only if the impersonated username is U".
- There is no way to express that e.g. "principal P can impersonate username U,
  but only when the request is `get pods`".

## Solution space

The following are two possible solutions to the above limitations.

## Option 1: Compound authorization for each UserInfo part

API server submits `n` SubjectAccessReview requests, one for each of
the following:

- the username to impersonate (required)
  - If the username begins with `system:serviceaccount:`, then the resource is
    `serviceaccounts`, the `resourceName=<SA name>`, and
    `namespace=<SA namespace>`. The `system:serviceaccounts` and
    `system:serviceaccounts:<namespace>` groups are added implicitly.
  - If the username begins with `system:node:`, then the `resource=nodes`, and
    `resourceName=<node name>`. The `system:nodes` group is added implicitly.
  - Otherwise, `resource=users` and `resourceName=<username>`.
- every group to impersonate (if any)
  - `resource=groups` and `resourceName=<group name>`.
- the uid to impersonate (if any)
  - `resource=uids` and `resourceName=<uid>`.
- every userinfo extra key-value pair to impersonate (if any)
  - `resource=userextras/<key>` and `resourceName=<value>`.

Everything here is the same as for existing (unconstrained) impersonation,
except that:

- The verb is `constrainedimpersonate`
- The api group for resources `users` and `groups` has changed from `""` to `"authentication.k8s.io"`
- Nodes are handled like ServiceAccounts now too. Now the API server checks
  the `nodes` resource with `resourceName=<node name>`, instead of the previous
  behavior of checking both:
  - the `users` resource with `resourceName=system:node:<node name>` AND
  - the `groups` resource with `resourceName=system:nodes`.
- The `system:nodes` group is added implicitly when the `nodes` resource can be
  impersonated.

In this model, there is a way to express that "principal P can impersonate
userextra E"; relying on compound authorization for the other parts of the
userinfo.

## Option 2: One unified SubjectAccessReview for the whole UserInfo struct

API server only submits exactly one ("new") SubjectAccessReview
request, with action "constrainedimpersonate" to resource "users",
"serviceaccounts", or "nodes", in apigroup "authentication.k8s.io", the
username, ServiceAccount name, or node name as the resourceName. In addition,
the namespace is set when impersonating a service account.

The authorizer is responsible for returning the ALL the conditions that should
apply to:

- the impersonated principal's groups, uid, and extra attributes.
- the request verb.
- the request apiGroup, resourceCombined, namespace, name.

The API server enforces that the conditions returned are satisfied by the request.

In this model, there is no easy way to express that "principal P can impersonate
userextra E"; relying on compound authorization for the other parts of the
userinfo. This will probably be pretty confusing to policy authors accustomed to
the compound authorization nature of Kubernetes. The policy author will have to
remember to add expressions like
`&& !(context.impersonatedPrincipal has groups)`, in order to prevent the
impersonator from impersonating groups (or uid, or extra, if this is not desired
in a specific case).

## Proposed solution

Option 1 is the most consistent one with existing Kubernetes behavior and the
Constrained Impersonation KEP, is a superset of/can express the behavior of
Option 2, and is the hardest to "shoot yourself in the foot" with. Thus the PoC
proceeds with Option 1.
