using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using XONT.Ventura.AppConsole;

namespace XONT.Ventura.TaskGateway.DAL
{
    public class AuthDAL
    {
        private readonly DBHelper _dbHelper;
        private readonly string _userDbConnectionString;
        private readonly string _systemDbConnectionString;
        private readonly IConfiguration _configuration;

        public AuthDAL(DBHelper dbHelper, IConfiguration configuration)
        {
            _configuration = configuration;
            _userDbConnectionString = _configuration.GetConnectionString("UserDB");
            _systemDbConnectionString = _configuration.GetConnectionString("SystemDB");
            _dbHelper = dbHelper;
        }

        public BusinessUnit GetBusinessUnit(string businessUnit, string distributorCode, ref string message)
        {
            var objBusinessUnit = new BusinessUnit();
            GetUserBusinessUnit(businessUnit, ref objBusinessUnit, distributorCode, ref message);
            return objBusinessUnit;
        }

        private void GetUserBusinessUnit(
            string businessUnit,
            ref BusinessUnit objBusinessUnit,
            string distributorCode,
            ref string message)
        {
            try
            {
                // Step 1: Get VAT & Logo from ZYBusinessUnit
                string businessUnitSQL = @"
            SELECT VATRegistrationNumber, Logo
            FROM dbo.ZYBusinessUnit
            WHERE BusinessUnit = @BusinessUnit";

                var buParam = new SqlParameter("@BusinessUnit", SqlDbType.NVarChar)
                {
                    Value = businessUnit.Trim()
                };

                DataTable dtBusinessUnit = _dbHelper.ExecuteQuery(
                    _systemDbConnectionString,
                    businessUnitSQL,
                    new[] { buParam }
                );

                if (dtBusinessUnit.Rows.Count > 0)
                {
                    objBusinessUnit.Logo = dtBusinessUnit.Rows[0]["Logo"]?.ToString() ?? "";
                }

                // Step 2: Get Distributor Info
                string distInfoSQL = @"
            SELECT 
                BusinessUnit, DistributorCode, DistributorName,
                AddressLine1, AddressLine2, AddressLine3,
                AddressLine4, AddressLine5,
                PostCode, TelephoneNumber, FaxNumber,
                EMailAddress, WebAddress, VATRegistrationNo
            FROM RD.Distributor
            WHERE BusinessUnit = @BusinessUnit
              AND DistributorCode = @DistributorCode
              AND Status = '1'";

                var distParams = new[]
                {
            new SqlParameter("@BusinessUnit", SqlDbType.NVarChar)
            {
                Value = businessUnit.Trim()
            },
            new SqlParameter("@DistributorCode", SqlDbType.NVarChar)
            {
                Value = distributorCode.Trim()
            }
        };

                DataTable dtDistributor = _dbHelper.ExecuteQuery(
                    _userDbConnectionString,
                    distInfoSQL,
                    distParams
                );

                if (dtDistributor.Rows.Count > 0)
                {
                    DataRow dtRow = dtDistributor.Rows[0];

                    objBusinessUnit.BusinessUnitCode = dtRow["BusinessUnit"]?.ToString() ?? "";
                    objBusinessUnit.BusinessUnitName = dtRow["DistributorName"]?.ToString()?.Trim() ?? "";
                    objBusinessUnit.AddressLine1 = dtRow["AddressLine1"]?.ToString()?.Trim() ?? "";
                    objBusinessUnit.AddressLine2 = dtRow["AddressLine2"]?.ToString()?.Trim() ?? "";
                    objBusinessUnit.AddressLine3 = dtRow["AddressLine3"]?.ToString()?.Trim() ?? "";
                    objBusinessUnit.AddressLine4 = dtRow["AddressLine4"]?.ToString()?.Trim() ?? ""; 
                    objBusinessUnit.AddressLine5 = dtRow["AddressLine5"]?.ToString()?.Trim() ?? ""; 
                    objBusinessUnit.PostCode = dtRow["PostCode"]?.ToString() ?? "";
                    objBusinessUnit.TelephoneNumber = dtRow["TelephoneNumber"]?.ToString() ?? "";
                    objBusinessUnit.FaxNumber = dtRow["FaxNumber"]?.ToString() ?? "";
                    objBusinessUnit.EmailAddress = dtRow["EMailAddress"]?.ToString() ?? "";
                    objBusinessUnit.VATRegistrationNumber = dtRow["VATRegistrationNo"]?.ToString() ?? "";
                    objBusinessUnit.WebAddress = dtRow["WebAddress"]?.ToString()?.Trim() ?? "";
                }
                else
                {
                    string fallbackSQL = @"
                SELECT 
                    BusinessUnit, BusinessUnitName,
                    AddressLine1, AddressLine2, AddressLine3,
                    AddressLine4, AddressLine5,
                    PostCode, TelephoneNumber, FaxNumber,
                    EmailAddress, VATRegistrationNumber, Logo, WebAddress
                FROM dbo.ZYBusinessUnit
                WHERE BusinessUnit = @BusinessUnit";

                    var fallbackParam = new SqlParameter("@BusinessUnit", SqlDbType.NVarChar)
                    {
                        Value = businessUnit.Trim()
                    };

                    DataTable dtFallback = _dbHelper.ExecuteQuery(
                        _systemDbConnectionString,
                        fallbackSQL,
                        new[] { fallbackParam }
                    );


                    if (dtFallback.Rows.Count > 0)
                    {
                        DataRow dtRow = dtFallback.Rows[0];

                        objBusinessUnit.BusinessUnitCode = dtRow["BusinessUnit"]?.ToString() ?? "";
                        objBusinessUnit.BusinessUnitName = dtRow["BusinessUnitName"]?.ToString() ?? "";
                        objBusinessUnit.AddressLine1 = dtRow["AddressLine1"]?.ToString() ?? "";
                        objBusinessUnit.AddressLine2 = dtRow["AddressLine2"]?.ToString() ?? "";
                        objBusinessUnit.AddressLine3 = dtRow["AddressLine3"]?.ToString() ?? "";
                        objBusinessUnit.AddressLine4 = dtRow["AddressLine4"]?.ToString() ?? "";
                        objBusinessUnit.AddressLine5 = dtRow["AddressLine5"]?.ToString() ?? "";
                        objBusinessUnit.PostCode = dtRow["PostCode"]?.ToString() ?? "";
                        objBusinessUnit.TelephoneNumber = dtRow["TelephoneNumber"]?.ToString() ?? "";
                        objBusinessUnit.FaxNumber = dtRow["FaxNumber"]?.ToString() ?? "";
                        objBusinessUnit.EmailAddress = dtRow["EmailAddress"]?.ToString() ?? "";
                        objBusinessUnit.VATRegistrationNumber = dtRow["VATRegistrationNumber"]?.ToString() ?? "";
                        objBusinessUnit.WebAddress = dtRow["WebAddress"]?.ToString()?.Trim() ?? "";
                    }
                }
            }
            catch (Exception ex)
            {
                message = $"GetUserBusinessUnit / {ex.Message}";
            }
        }


        public User GetUserInfo(string userName, string password, ref string message)
        {
            User user = GetUserMainData(userName, password,ref message);
            //VR003 Begin
            if (user == null)
            {
                return null;
            }
            //VR003 End

            if (user.AlreadyLogin != null)
            {
                if (user.isExists && (user.AlreadyLogin.Equals(string.Empty)))
                {
                    GetUserRoles(userName,ref user, ref message);
                }
            }
            else
            { return user; }

            return user;
        }
        private User GetUserMainData(string userName, string password, ref string message)
        {
            User user = new User();
            string encriptPass = password; // VR029: assuming password is already encrypted
            try
            {
                string spName = "[dbo].[usp_GetUserData]";

                var parameters = new[]
                {
            new SqlParameter("@UserName", SqlDbType.NVarChar, 50)
            {
                Value = userName.Trim()
            },
            new SqlParameter("@Password", SqlDbType.NVarChar, 100)
            {
                Value = encriptPass
            },
            new SqlParameter("@ExecutionType", SqlDbType.Char, 1)
            {
                Value = "1"
            },
            new SqlParameter("@DefaultBusinessUnit", SqlDbType.Char, 1)
            {
                Value = "1"
            }
        };

                DataTable dtResult = _dbHelper.ExecuteStoredProcedure(
                    _systemDbConnectionString,
                    spName,
                    parameters
                );

                if (dtResult.Rows.Count > 0)
                {
                    string activeFlag = "";
                    foreach (DataRow row in dtResult.Rows)
                    {
                        user.isExists = true;
                        user.BusinessUnit = row["BusinessUnit"]?.ToString();
                        user.UserName = row["UserName"]?.ToString();
                        user.UserFullName = row["UserFullName"]?.ToString();
                        user.UserLevelGroup = row["UserLevelGroup"]?.ToString();
                        user.Password = row["Password"]?.ToString();
                        user.PasswordLocked = Convert.ToChar(row["PasswordLocked"]);
                        activeFlag = row["ActiveFlag"]?.ToString();
                        user.PowerUser = row["PowerUser"]?.ToString();
                        user.Theme = row["Theme"]?.ToString();
                        user.Language = row["Language"]?.ToString();
                        user.CaptionEditor = row["CaptionEditor"]?.ToString().Trim() == "1"; // V2033
                        user.FontColor = row["FontColor"]?.ToString();
                        user.FontSize = int.TryParse(row["FontSize"]?.ToString(), out int fontSize) ? fontSize : 0;
                        user.FontName = row["FontName"]?.ToString();
                        user.HasProPicture = row["ProPicAvailable"]?.ToString().Length > 0 ? row["ProPicAvailable"].ToString()[0] : '\0'; // New Ventura
                        user.DefaultRoleCode = row["RoleCode"]?.ToString(); // v2014

                        // Distributor Code - VR002
                        string distributorCode = row["DistributorCode"]?.ToString();
                        user.DistributorCode = string.IsNullOrEmpty(distributorCode) ? null : distributorCode.Trim();

                        // VR013
                        user.RestrictFOCInvoice = row["RestrictFOCInvoice"]?.ToString() ?? "0";

                        // VR024
                        user.SupplierCode = row["SupplierCode"]?.ToString()?.Trim() ?? "";
                        user.CustomerCode = row["CustomerCode"]?.ToString()?.Trim() ?? "";

                        // VR028
                        user.ExecutiveCode = row["ExecutiveCode"]?.ToString()?.Trim() ?? "";

                        // V2004
                        user.PasswordChange = row["PasswordChange"]?.ToString() ?? "";

                        // V2042
                        user.POReturnAuthorizationLevel = row["POReturnAuthorizationLevel"]?.ToString() ?? "";
                        user.POReturnAuthorizationUpTo = row["POReturnAuthorizationUpTo"]?.ToString() ?? "";

                        // V2048
                        user.PUSQQtyEdit = row["PUSQQtyEdit"]?.ToString() ?? "";
                    }
                    return user;


                }
                else
                {
                    return null;
                }
            }
            catch (Exception ex)
            {
                message = $"GetUserMainData / {ex.Message}";
                return null;
            }
        }
        private void GetUserRoles(string userName,ref User user, ref string message)
        {
            var userRoles = new List<UserRole>();
            try
            {
                if (userName.Trim() != "administrator") // VR006
                {
                    string commandText = @"
                SELECT ZYUserRole.RoleCode, ZYRole.Description, ZYRole.Icon
                FROM ZYUser
                INNER JOIN ZYUserRole ON ZYUser.UserName = ZYUserRole.UserName
                INNER JOIN ZYRole ON ZYUserRole.RoleCode = ZYRole.RoleCode
                WHERE ZYUser.UserName = @UserName
                ORDER BY ZYUserRole.Sequence";

                    var parameter = new SqlParameter("@UserName", SqlDbType.NVarChar, 50)
                    {
                        Value = userName.Trim()
                    };

                    DataTable dtResult = _dbHelper.ExecuteQuery(
                        _systemDbConnectionString,
                        commandText,
                        new[] { parameter }
                    );

                    foreach (DataRow row in dtResult.Rows)
                    {
                        userRoles.Add(new UserRole
                        {
                            RoleCode = row["RoleCode"]?.ToString() ?? "",
                            Description = row["Description"]?.ToString() ?? "",
                            Icon = row["Icon"]?.ToString()?.Trim() ?? ""
                        });
                    }
                }
                else
                {
                    // VR006: Special case for administrator
                    userRoles.Add(new UserRole
                    {
                        RoleCode = "05_ROLE",
                        Description = "SYSTEM",
                        Icon = "role1.png"
                    });
                }

                user.UserRoles = userRoles;
            }
            catch (Exception ex)
            {
                message = $"GetUserRoles {ex.Message}";
            }
        }

        public DataTable GetUnAuthorizedTasks(string userName, ref string message)
        {
            try
            {
                string spName = "[dbo].[usp_GetUnAuthorizedTasks]";

                var parameters = new[]
                {
                new SqlParameter("@UserName", SqlDbType.NVarChar, 50)
                { Value = (object)userName ?? DBNull.Value }
                };

                return _dbHelper.ExecuteStoredProcedure(
                    _systemDbConnectionString,
                    spName,
                    parameters
                );

            }
            catch (Exception ex)
            {
                message = $"GetUnAuthorizedTasks / {ex.Message}";
                return new DataTable();
            }
        }
    }
}
