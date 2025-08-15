
using System.Reflection;

namespace XONT.Ventura.TaskGateway.Infrastructure
{
    public static class PluginLoader
    {
        public static void LoadAssembliesAndRegisterServices(IServiceCollection services, string pluginDirectory)
        {
            if (!Directory.Exists(pluginDirectory))
            {
                Console.WriteLine($"Plugin folder not found: {pluginDirectory}. No plugins loaded.");
                return;
            }

            var loadedAssemblies = new List<Assembly>();

            foreach (var dllPath in Directory.GetFiles(pluginDirectory, "*.dll"))
            {
                try
                {
                    var assembly = Assembly.LoadFrom(dllPath);
                    loadedAssemblies.Add(assembly);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Failed to load {dllPath}: {ex.Message}");
                }
            }

            foreach (var assembly in loadedAssemblies)
            {
                var assemblyName = assembly.GetName().Name;

                if (assemblyName.EndsWith(".Web", StringComparison.OrdinalIgnoreCase))
                {
                    services.AddControllers().AddApplicationPart(assembly);
                    continue;
                }

                if (!assemblyName.EndsWith(".BLL", StringComparison.OrdinalIgnoreCase) &&
                    !assemblyName.EndsWith(".DAL", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                RegisterServicesFromAssembly(services, assembly);
            }
        }

        private static void RegisterServicesFromAssembly(IServiceCollection services, Assembly assembly)
        {
            var types = assembly.GetTypes()
                .Where(t => t.IsClass && !t.IsAbstract && !t.IsInterface && !t.Name.StartsWith("<"))
                .ToList();

            foreach (var type in types)
            {
                var serviceInterface = type.GetInterface($"I{type.Name}");
                if (serviceInterface != null)
                {
                    services.AddScoped(serviceInterface, type);
                }
                else
                {
                    services.AddScoped(type);
                }
            }
        }
    }
}
