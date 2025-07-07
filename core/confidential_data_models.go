package core

type BaseVersionedConfidentialDataJsonModel struct {
	Uuid   string   `json:"u"`
	Type   string   `json:"t"`
	Labels []string `json:"l,omitempty"`
}

func (b *BaseVersionedConfidentialDataJsonModel) From(data VersionedConfidentialData) {
	b.Uuid = data.GetUUID()
	b.Type = data.GetType()
	b.Labels = data.GetLabels()
}

func (b *BaseVersionedConfidentialDataJsonModel) Into(data SettableVersionedConfidentialData) {
	data.SetUUID(b.Uuid)
	data.SetType(b.Type)
	data.SetLabels(b.Labels)
}

type BaseVersionedConfidentialDataStruct struct {
	Uuid   string
	Type   string
	Labels []string
}

func (b *BaseVersionedConfidentialDataStruct) GetUUID() string {
	return b.Uuid
}

func (b *BaseVersionedConfidentialDataStruct) GetType() string {
	return b.Type
}

func (b *BaseVersionedConfidentialDataStruct) GetLabels() []string {
	return b.Labels
}

func (b *BaseVersionedConfidentialDataStruct) SetUUID(v string) {
	b.Uuid = v
}

func (b *BaseVersionedConfidentialDataStruct) SetType(v string) {
	b.Type = v
}

func (b *BaseVersionedConfidentialDataStruct) SetLabels(strings []string) {
	b.Labels = strings
}
