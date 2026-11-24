package hubconn

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/resolver/manual"
	"google.golang.org/grpc/test/bufconn"
)

// p4n-W5b-r3-8: a service config that comes with the resolver's answer (gRPC reads
// one from a TXT record of the hub's name) must not steer the client. The manual
// resolver hands over a config that would refuse every reply, as a forged TXT
// answer could.
func TestServiceConfigFromTheResolverIsIgnored(t *testing.T) {
	lis := bufconn.Listen(1 << 16)
	srv := grpc.NewServer()
	healthpb.RegisterHealthServer(srv, health.NewServer())
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	r := manual.NewBuilderWithScheme("ctrlz")
	r.BuildCallback = func(_ resolver.Target, cc resolver.ClientConn, _ resolver.BuildOptions) {
		scp := cc.ParseServiceConfig(`{"methodConfig":[{"name":[{}],"maxResponseMessageBytes":1}]}`)
		if scp.Err != nil {
			t.Error(scp.Err)
			return
		}
		r.InitialState(resolver.State{Addresses: []resolver.Address{{Addr: "hub"}}, ServiceConfig: scp})
	}
	opts := append(Options(RoleControl, insecure.NewCredentials()),
		grpc.WithResolvers(r),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }))
	cc, err := grpc.NewClient("ctrlz:///hub", opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := healthpb.NewHealthClient(cc).Check(ctx, &healthpb.HealthCheckRequest{}); err != nil {
		t.Fatalf("a service config from the resolver steered the client: %v", err)
	}
}
