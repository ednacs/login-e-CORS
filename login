using Exo.WebApi.Contexts;
using Exo.WebApi.Models;
using System.Collections.Generic;
using System.Linq;
namespace Exo.WebApi.Repositories
{
    public class UsuarioRepository
    {
        private readonly ExoContext _context;
        public UsuarioRepository(ExoContext context)
        {
            _context = context;
        }
        public Usuario Login(string email, string senha)
        {
            return _context.Usuarios.FirstOrDefault(u => u.Email == 
email && u.Senha == senha);
        }
        public List<Usuario> Listar()
        {
            return _context.Usuarios.ToList();
        }
        public void Cadastrar(Usuario usuario)
        {
            _context.Usuarios.Add(usuario);
            _context.SaveChanges();
        }
        public Usuario BuscaPorId(int id)
        {       
            return _context.Usuarios.Find(id);
        }
        public void Atualizar(int id, Usuario usuario)
        {
            Usuario usuarioBuscado = _context.Usuarios.Find(id);
            if (usuarioBuscado != null)
            {
                usuarioBuscado.Email = usuario.Email;
                usuarioBuscado.Senha = usuario.Senha;
            }
            _context.Usuarios.Update(usuarioBuscado);
            _context.SaveChanges();
        }
        public void Deletar(int id)
        {
            Usuario usuarioBuscado = _context.Usuarios.Find(id);
            _context.Usuarios.Remove(usuarioBuscado);
            _context.SaveChanges();
        }
        public Usuario Login(string email, string senha)
        {
        return _context.Usuarios.FirstOrDefault(u => u.Email == 
        email && u.Senha == senha);
        }
     }
}


<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net6.0</TargetFramework>
    <Nullable>disable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Swashbuckle.AspNetCore" Version="6.2.3"/>
    <PackageReference Include="Microsoft.VisualStudio.Web.CodeGeneration.Design" Version="6.0.0"/>
    <PackageReference Include="Microsoft.EntityFrameworkCore" Version="6.0.0"/>
    <PackageReference Include="Microsoft.EntityFrameworkCore.SqlServer" Version="6.0.0"/>
    <PackageReference Include="Microsoft.AspNetCore.Authentication.JwtBearer" Version="6.0.0"/>
    <PackageReference Include="Microsoft.EntityFrameworkCore.Tools.DotNet" Version="2.0.1"/>
  </ItemGroup>
</Project>

using Exo.WebApi.Models;
using Exo.WebApi.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
namespace Exo.WebApi.Controllers
{
    [Produces("application/json")]
    [Route("api/[controller]")]
    [ApiController]
    public class UsuariosController : ControllerBase
    {
        private readonly UsuarioRepository _usuarioRepository;
        public UsuariosController(UsuarioRepository
usuarioRepository)
        {
        _usuarioRepository = usuarioRepository;
        }
        // get -> /api/usuarios
        [HttpGet]
        public IActionResult Listar()
        {
            return Ok(_usuarioRepository.Listar());
        }
        // post -> /api/usuarios
        // [HttpPost]
        // public IActionResult Cadastrar(Usuario usuario)
        // {
        //     _usuarioRepository.Cadastrar(usuario);
        //     return StatusCode(201);
// Novo código POST para auxiliar o método de Login.
public IActionResult Post(Usuario usuario)
{
Usuario usuarioBuscado = _usuarioRepository.Login(usuario.Email, 
usuario.Senha);
if (usuarioBuscado == null)
{
return NotFound("E-mail ou senha inválidos!");
}
// Se o usuário for encontrado, segue a criação do token.
// Define os dados que serão fornecidos no token - Payload.
var claims = new[]
{
// Armazena na claim o e-mail usuário autenticado.
new Claim(JwtRegisteredClaimNames.Email, usuarioBuscado.Email),
// Armazena na claim o id do usuário autenticado.
new Claim(JwtRegisteredClaimNames.Jti, 
usuarioBuscado.Id.ToString()),
};
// Define a chave de acesso ao token.
var key = new
SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes("exoapi-chaveautenticacao"));
// Define as credenciais do token.
var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
// Gera o token.
var token = new JwtSecurityToken(
issuer: "exoapi.webapi", // Emissor do token.
audience: "exoapi.webapi", // Destinatário do token.
claims: claims, // Dados definidos acima.
expires: DateTime.Now.AddMinutes(30), // Tempo de expiração.
signingCredentials: creds // Credenciais do token.
);
// Retorna ok com o token.
return Ok(
new { token = new JwtSecurityTokenHandler().WriteToken(token) }
);
}
// Fim do novo código POST para auxiliar o método de Login

        }
        // get -> /api/usuarios/{id}
        [HttpGet("{id}")] // Faz a busca pelo ID.
        public IActionResult BuscarPorId(int id)
        {
            Usuario usuario = _usuarioRepository.BuscaPorId(id);
            if (usuario == null)
            {
                return NotFound();
            }
            return Ok(usuario);
        }
        // put -> /api/usuarios/{id}
        // Atualiza.
        [Authorize]
        [HttpPut("{id}")]
       
        public IActionResult Atualizar(int id, Usuario usuario)
        {
            _usuarioRepository.Atualizar(id, usuario);
            return StatusCode(204);
        }
        // delete -> /api/usuarios/{id}
        [Authorize]
        [HttpDelete("{id}")]

       
        public IActionResult Deletar(int id)
        {
            try
            {
                _usuarioRepository.Deletar(id);
                return StatusCode(204);
            }
            catch (Exception e)
            {
                return BadRequest();
            }
        }
    }
}


using Microsoft.IdentityModel.Tokens;
using Exo.WebApi.Contexts;
using Exo.WebApi.Repositories;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddScoped<ExoContext, ExoContext>();
builder.Services.AddControllers();
/ Forma de autenticacão.
builder.Services.AddAuthentication(options =>
{
options.DefaultAuthenticateScheme = "JwtBearer";
options.DefaultChallengeScheme = "JwtBearer";
})
// Parâmetros de validacão do token.
.AddJwtBearer("JwtBearer", options =>
{
options.TokenValidationParameters = new TokenValidationParameters
{
// Valida quem está solicitando.
ValidateIssuer = true,
// Valida quem está recebendo.
ValidateAudience = true,
// Define se o tempo de expiração será validado.
ValidateLifetime = true,
// Criptografia e validação da chave de autenticacão.
IssuerSigningKey = new
SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes("exoapi-chaveautenticacao")),
// Valida o tempo de expiração do token.
ClockSkew = TimeSpan.FromMinutes(30),
// Nome do issuer, da origem.
ValidIssuer = "exoapi.webapi",
// Nome do audience, para o destino.
ValidAudience = "exoapi.webapi"
};
});
builder.Services.AddTransient<ProjetoRepository, ProjetoRepository>();
builder.Services.AddTransient<UsuarioRepository, UsuarioRepository>();

var app = builder.Build();

app.UseRouting();
// Habilita a autenticação.
app.UseAuthentication();
// Habilita a autorização.
app.UseAuthorization();


app.UseEndpoints(endpoints =>
{
    endpoints.MapControllers();
});

app.Run();
