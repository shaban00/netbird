package birddrop

type owner struct {
	uid, gid int
	sid      string
}

// ReceiveOption adjusts how Receive hands received files to the local user.
type ReceiveOption func(*owner)

// WithOwnerSID hands received files to the Windows account with this SID: it
// becomes the owner and is granted full control
func WithOwnerSID(sid string) ReceiveOption {
	return func(o *owner) { o.sid = sid }
}
