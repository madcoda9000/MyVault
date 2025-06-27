using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace MyVault.Server.Middleware
{
    /// <summary>
    /// swagger schema filter class, inherited from ISchemFilter
    /// </summary>
    public class SwaggerSchemaFilter :ISchemaFilter
    {
        private readonly string[] VisibleSchemas = {  };

        /// <summary>
        /// swagger schema filter
        /// </summary>
        /// <param name="schema"></param>
        /// <param name="context"></param>
        public void Apply(OpenApiSchema schema, SchemaFilterContext context)
        {
            foreach(var key in context.SchemaRepository.Schemas.Keys)
            {
                if (!VisibleSchemas.Contains(key))
                    context.SchemaRepository.Schemas.Remove(key);
            }
        }
    }
}
