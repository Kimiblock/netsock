# charcoal
A filter for sandboxes

---

# Environment variables:

- `RUNTIME_DIRECTORY`: specify where charcoal should place the control socket in. A sensible default is `/run/charcoal`, set by systemd. Which makes charcoal listen on `/run/charcoal/control.sock`.
	* Downstream apps may not support different socket path

---

# Requests:

- `/add`: with a JSON which contains:

```
type IncomingSig struct {
	CgroupNested	string
	RawDenyList	string
	SandboxEng	string
	AppID		string
}
```

This returns a JSON containing:

```
type ResponseSignal struct {
	Success bool
	Log     string
}
```