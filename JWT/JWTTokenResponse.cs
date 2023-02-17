namespace edu_back.JWT;

public class JWTTokenResponse
{
    public string? AccessToken { get; set; }

    public string? RefreshToken { get; set; }
}