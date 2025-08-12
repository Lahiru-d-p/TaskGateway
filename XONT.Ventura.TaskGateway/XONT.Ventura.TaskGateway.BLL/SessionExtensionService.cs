using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using System.Data;
using System.Text.Json;

namespace XONT.Ventura.TaskGateway.BLL
{
    public static class SessionExtensionService
    {

        private const string XmlPrefix = "Xml_";
        public static void SetObject<T>(this ISession session, string key, T value)
        {
            session.SetString(key, JsonSerializer.Serialize(value));
        }

        public static T? GetObject<T>(this ISession session, string key)
        {
            var value = session.GetString(key);
            return value == null ? default : JsonSerializer.Deserialize<T>(value);
        }

        public static void SetDataTable(this ISession session, string key, DataTable table)
        {
            if (session == null || table == null) return;

            using (var sw = new StringWriter())
            {
                table.WriteXml(sw, XmlWriteMode.WriteSchema);
                session.SetString(XmlPrefix + key, sw.ToString());
            }
        }

        public static DataTable? GetDataTable(this ISession session, string key)
        {
            if (session == null) return default;

            var xml = session.GetString(XmlPrefix + key);
            if (string.IsNullOrEmpty(xml)) return default;

            var table = new DataTable();
            using (var sr = new StringReader(xml))
            {
                table.ReadXml(sr);
            }

            return table;
        }
    }
}