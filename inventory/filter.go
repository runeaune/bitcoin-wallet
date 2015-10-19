package inventory

import (
	"bytes"
	"fmt"

	"github.com/aarbt/bitcoin-wallet/messages"
)

// TODO make threadsafe
type Filter struct {
	local  map[string]bool
	remote *messages.FilterLoad
	// Remote filter needs to be updated. This usualy implies rescanning
	// history.
	remoteUpdate bool

	// Statisitics
	lookups        int
	matches        int
	falsePositives int
}

func NewFilter() *Filter {
	var err error
	f := Filter{
		local: make(map[string]bool),
	}
	f.remote, err = messages.NewFilterLoad(1000, 10)
	if err != nil {
		panic(fmt.Sprintf("Error creating filter: %v", err))
	}
	f.remote.Flags = messages.BloomUpdateAll
	return &f
}

func (f Filter) String() string {
	return fmt.Sprintf("Filter with %d elements. %d lookups, %d matches, %d false positives.",
		len(f.local), f.lookups, f.matches, f.falsePositives)
}

const (
	filterNoUpdateNeeded = false
	filterMayNeedUpdate  = true
)

func (f *Filter) Watch(data []byte, mayNeedUpdate bool) {
	f.remote.AddData(data)
	// TODO only set this flag if the filter actually changed.
	if mayNeedUpdate {
		f.remoteUpdate = true
	}

	f.local[string(data)] = true
}

func (f *Filter) RemoteUpdateNeeded() bool {
	return f.remoteUpdate
}

func (f *Filter) Filter() *messages.FilterLoad {
	return f.remote
}

func (f *Filter) RemoteData() []byte {
	var b bytes.Buffer
	f.remote.Serialize(&b)
	return b.Bytes()
}

func (f *Filter) Match(data []byte) bool {
	f.lookups++
	if f.local[string(data)] {
		f.matches++
		if !f.remote.MayContain(data) {
			f.falsePositives++
		}
		return true
	}
	return false
}
