# vManage Go SDK for the egress-watcher

A library for interacting with **vManage** in go, specifically made for the
egress-watcher project.

## Quickstart

Get a client:

```go
cl, err := vmanagego.NewClient(context.Background(), "https://<address>:<port>", "<username>", "<password>")
if err != nil {
    fmt.Println("cannot get a vManage client:", err)
    return
}

// Use the client
_ = cl
```

> If you have a *self-signed certificate* then you have to add
> `vmanagego.WithSkipInsecure()` in the above code, like so:
>
> ```go
> vmanagego.NewClient(context.Background(), "https://<address>:<port>", "<username>", "<password>", vmanagego.WithSkipInsecure())
> ```

Now you can use the client by "scoping" the operation. For example, if you want
to work with *custom applications*:

```go
// Scope the operation: we're going to work with custom applications.
cacl := cl.CustomApplications()

// Define the options that the Create function will take: these define the data
// about the custom application.
// Note: here "customapp" is the customapp package included in this library.
createOpts := customapp.CreateOptions{
    Name:        "my-custom-app",
    ServerNames: []string{ "custom.example.com", "api.custom.example.com" },
    L3L4Attributes: customapp.L3L4Attributes{
        TCP: []customapp.IPsAndPorts{
            {
                IPs: []string{  "11.22.33.44", "22.33.44.55" },
                Ports: &customapp.Ports{
                    Values: []int32{ 80, 8080, 443 },
                    Ranges: [][2]int32{{ 9000, 9010 }},
                },
            },
        },
    },
}

// Create the custom application
appID, err := cacl.Create(context.Background(), createOpts)
if err != nil {
    fmt.Println("error while creating custom app:", err)
    return
}

fmt.Println("custom application created, ID returned is", *appID)
```

Or if you want to list all *AppRoute policies* -- a more "condensed" example:

```go
// Get the list...
appRoutePols, err := cl.AppRoute().List(context.Background())
if err != nil {
    fmt.Println("cannot list approute policies", err)
    return
}

// ... and do something with it
for _, pol := range appRoutePols {
    fmt.Printf(`retrieved policy "%s" with ID %s\n`, pol.Name, pol.ID)
}
```

Or, finally, the library helps you in performing some async operations:

```go
// Do something here that will trigger a long operation in vManage, which will
// return us an operation ID...

// Create a channel that will notify us when the operation finished on vManage
waitChan := make(chan struct{})

// Wait for the operation to finish in a separate goroutine...
go func(){
    // When we're done waiting, we are going to close this channel, so that
    // we will unblock the main goroutine (down below).
    defer close(waitChan)

    // Suppose that operationID has been returned by vManage, specifying that
    // hasn't finished applying some configuration yet.
    _, err := cl.Status().WaitForOperationToFinish(context.Background(), status.WaitOptions{
        OperationID: *operationID,
    })
    if err != nil {
        fmt.Println("error while waiting", err)
        return
    }
}

// Continue doing other stuff while the previous goroutine waits...

// ... Still do other stuff...

// ... Other meaningful stuff...

// At this point we can't go on anymore, because for reasons we can only
// continue if vManage is finished with that operation. So we block waiting
// for the channel to be closed or a result is inserted into it.
// NOTE: this is a simplicist algorithm! You should check if the operation
// was successful by checking the first returned variable.
<- waitChan

// We're now unblocked!
fmt.Println("vManage finished working!")

// Now do stuff that depends on the previous operation, now that it finished.

```

## Extend the SDK

The best way to extend the SDK and add functionality is to look at the source
code and create your own scoped operations. For example, if you want to add
*Policy Data* operations, create your structure like this:

```go
type policyDataOps struct {
    // Requester is the package that will perform all your operations.
    // Look at the source code to learn how to quickly use it.
    *r.Requester
}

func (c *Client) Status() *policyDataOps {
    const (
        pathPolicyDataBaseURL string = "/template/policy/definition/data"
    )

    return &policyDataOps{
        Requester: req.CloneWithNewBasePath(pathPolicyDataBaseURL),
    }
}

// Define your options as you want in your code.
func (p *policyDataOps) Create(ctx context.Context, opts options) {
    // create your request body here...

    // Do() actually calls the Requester.Do(). Here we are taking advantage of
    // go's method encapsulation: this is the same as doing p.Requester.Do()
    response, err := p.Do(ctx, r.WithPOST(), r.WithBodyBytes(requestBody))
    // Check the error...

    // Unmarshal the response body...
    // Note: the SDK will already give you the `data` field in the response
    // body without you doing anything else, unless there is no `data` field,
    // in which case you will have to unmarshal the whole body on your own.
}
```
