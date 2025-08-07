IF EXISTS (SELECT * FROM sys.objects WHERE object_id = OBJECT_ID(N'[dbo].[usp_GetUnAuthorizedTasks]') AND type in (N'P', N'PC'))
DROP PROCEDURE [dbo].[usp_GetUnAuthorizedTasks]
GO

SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
-- =============================================
-- Author:		Lahiru
-- Last Modified Version: 4.0.0.0
-- Description:	Get URLs for login user for tasks without access
-- =============================================
CREATE PROCEDURE  [dbo].[usp_GetUnAuthorizedTasks]
-- Parameters
@UserName char(30)=''
AS
BEGIN
	SELECT TaskCode, ExecutionScript AS [url] 
	FROM dbo.ZYTask
	WHERE TaskCode NOT IN
	(
		SELECT T.TaskCode
		FROM dbo.ZYUserRole AS UR 
		INNER JOIN dbo.ZYRoleMenu AS RM ON RM.RoleCode = UR.RoleCode
		INNER JOIN dbo.ZYMenuDetail AS MD ON RM.MenuCode = MD.MenuCode
		INNER JOIN dbo.ZYTask AS T ON T.TaskCode = MD.TaskCode
		WHERE UR.UserName = @UserName
	);
END