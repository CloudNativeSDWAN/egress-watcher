package sdwan

type OperationType string

const (
	OperationRemove OperationType = "remove"
	OperationAdd    OperationType = "add"
)

type Operation struct {
	Type            OperationType
	ApplicationName string
	Servers         []string
}
