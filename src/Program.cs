using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Microsoft.Fast.Components.FluentUI;

namespace CIDRCalc;

public class Program
{
    public static async Task Main(string[] args)
    {
        var builder = WebAssemblyHostBuilder.CreateDefault(args);
        builder.RootComponents.Add<App>("#app");
        builder.Services.AddFluentUIComponents(options =>
        {
            options.HostingModel = BlazorHostingModel.WebAssembly;
        });

        await builder.Build().RunAsync();
    }
}