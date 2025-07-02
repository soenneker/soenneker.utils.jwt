using Soenneker.Utils.Jwt.Abstract;
using Soenneker.Tests.FixturedUnit;
using Xunit;


namespace Soenneker.Utils.Jwt.Tests;

[Collection("Collection")]
public class JwtUtilTests : FixturedUnitTest
{
    private readonly IJwtUtil _util;

    public JwtUtilTests(Fixture fixture, ITestOutputHelper output) : base(fixture, output)
    {
        _util = Resolve<IJwtUtil>(true);
    }

    [Fact]
    public void Default()
    {

    }
}
