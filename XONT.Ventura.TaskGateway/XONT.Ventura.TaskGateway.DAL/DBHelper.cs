using Microsoft.Data.SqlClient;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace XONT.Ventura.TaskGateway.DAL
{
    public class DBHelper
    {

        #region Query Methods

        public DataTable ExecuteQuery(string connectionString, string query, SqlParameter[] parameters = null)
        {
            var dataTable = new DataTable();
            using (var conn = new SqlConnection(connectionString))
            using (var cmd = new SqlCommand(query, conn))
            {
                if (parameters != null)
                    cmd.Parameters.AddRange(parameters);

                using (var adapter = new SqlDataAdapter(cmd))
                {
                    adapter.Fill(dataTable);
                }
            }
            return dataTable;
        }

        public object ExecuteScalar(string connectionString, string query, SqlParameter[] parameters = null)
        {
            using (var conn = new SqlConnection(connectionString))
            using (var cmd = new SqlCommand(query, conn))
            {
                cmd.CommandType = CommandType.Text;
                if (parameters != null)
                    cmd.Parameters.AddRange(parameters);

                conn.Open();
                return cmd.ExecuteScalar();
            }
        }

        #endregion

        #region NonQuery Methods

        public int ExecuteNonQuery(string connectionString, string query, SqlParameter[] parameters = null)
        {
            using (var conn = new SqlConnection(connectionString))
            using (var cmd = new SqlCommand(query, conn))
            {
                cmd.CommandType = CommandType.Text;
                if (parameters != null)
                    cmd.Parameters.AddRange(parameters);

                conn.Open();
                return cmd.ExecuteNonQuery();
            }
        }

        #endregion

        #region Stored Procedure Methods

        public DataTable ExecuteStoredProcedure(string connectionString, string spName, SqlParameter[] parameters = null)
        {
            var dataTable = new DataTable();
            using (var conn = new SqlConnection(connectionString))
            using (var cmd = new SqlCommand(spName, conn))
            {
                cmd.CommandType = CommandType.StoredProcedure;
                if (parameters != null)
                    cmd.Parameters.AddRange(parameters);

                using (var adapter = new SqlDataAdapter(cmd))
                {
                    adapter.Fill(dataTable);
                }
            }
            return dataTable;
        }

        public SqlParameter ExecuteStoredProcedureWithOutputParameter(string connectionString, string spName, SqlParameter[] parameters = null)
        {
            using (var conn = new SqlConnection(connectionString))
            using (var cmd = new SqlCommand(spName, conn))
            {
                cmd.CommandType = CommandType.StoredProcedure;
                if (parameters != null)
                    cmd.Parameters.AddRange(parameters);

                conn.Open();
                cmd.ExecuteNonQuery();

                return cmd.Parameters
                    .Cast<SqlParameter>()
                    .FirstOrDefault(p => p.Direction == ParameterDirection.Output);
            }
        }

        public List<SqlParameter> ExecuteStoredProcedureWithOutputParameters(string connectionString, string spName, SqlParameter[] parameters = null)
        {
            using (var conn = new SqlConnection(connectionString))
            using (var cmd = new SqlCommand(spName, conn))
            {
                cmd.CommandType = CommandType.StoredProcedure;
                if (parameters != null)
                    cmd.Parameters.AddRange(parameters);

                conn.Open();
                cmd.ExecuteNonQuery();

                return cmd.Parameters
                    .Cast<SqlParameter>()
                    .Where(p => p.Direction == ParameterDirection.Output)
                    .ToList();
            }
        }

        #endregion

        #region Reader Methods

        public List<T> ExecuteReader<T>(string connectionString, string query, SqlParameter[] parameters = null, Func<SqlDataReader, T> map = null)
        {
            var list = new List<T>();
            using (var conn = new SqlConnection(connectionString))
            using (var cmd = new SqlCommand(query, conn))
            {
                if (parameters != null)
                    cmd.Parameters.AddRange(parameters);

                conn.Open();
                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        if (map != null)
                            list.Add(map(reader));
                    }
                }
            }
            return list;
        }

        #endregion
    }
}