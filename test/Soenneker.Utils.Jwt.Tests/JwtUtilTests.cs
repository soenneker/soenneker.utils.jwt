using Soenneker.Utils.Jwt.Abstract;
using Soenneker.Tests.HostedUnit;


namespace Soenneker.Utils.Jwt.Tests;

[ClassDataSource<Host>(Shared = SharedType.PerTestSession)]
public class JwtUtilTests : HostedUnitTest
{
    private readonly IJwtUtil _util;

    public JwtUtilTests(Host host) : base(host)
    {
        _util = Resolve<IJwtUtil>(true);
    }

    [Test]
    public void Default()
    {

    }
}
