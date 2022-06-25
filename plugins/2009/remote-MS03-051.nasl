###################################################################
# OpenVAS Vulnerability Test
# $Id: remote-MS03-051.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# Microsoft Security Bulletin MS03-051
# Buffer Overrun in Microsoft FrontPage Server Extensions Could Allow Code Execution
# SmartHTML interpreter denial of service vulnerability: CAN-2003-0824
#
# Affected Software:
# Microsoft Windows 2000 Service Pack 2, Service Pack 3
# Microsoft Windows XP, Microsoft Windows XP Service Pack 1
# Microsoft Windows XP 64-Bit Edition, Microsoft Windows XP 64-Bit Edition Service Pack 1
# Microsoft Office XP, Microsoft Office XP Service Pack 1, Service Pack 2
# Microsoft Office 2000 Server Extensions
#
# Non Affected Software:
# Microsoft Windows Millennium Edition
# Microsoft Windows NT Workstation 4.0, Service Pack 6a
# Microsoft Windows NT Server 4.0, Service Pack 6a
# Microsoft Windows NT Server 4.0, Terminal Server Edition, Service Pack 6
# Microsoft Windows 2000 Service Pack 4
# Microsoft Windows XP 64-Bit Edition Version 2003
# Microsoft Windows Server 2003 (Windows SharePoint Services)
# Microsoft Windows Server 2003 64-Bit Edition (Windows SharePoint Services)
# Microsoft Office System 2003
#
# Tested Microsoft Windows and Office Components:
# Affected Components:
# Microsoft FrontPage Server Extensions 2000 (For Windows NT4) and Microsoft Office 2000 Server Extensions (Shipped with Office 2000)
# Download the update: http://www.microsoft.com/downloads/details.aspx?FamilyId=C84C3D10-A821-4819-BF58-D3BC70A77BFA&displaylang=en
# Microsoft FrontPage Server Extensions 2000 (Shipped with Windows 2000)
# Download the update: http://www.microsoft.com/downloads/details.aspx?FamilyId=057D5F0E-0E2B-47D2-9F0F-3B15DD8622A2&displaylang=en
# Microsoft FrontPage Server Extensions 2000 (Shipped with Windows XP)
# Download the update: http://www.microsoft.com/downloads/details.aspx?FamilyId=9B302532-BFAB-489B-82DC-ED1E49A16E1C&displaylang=en
# Microsoft FrontPage Server Extensions 2000 64-bit (Shipped with Windows XP 64-bit)
# Download the update: http://www.microsoft.com/downloads/details.aspx?FamilyId=153A476F-F530-4035-B858-D56FC8A7010F&displaylang=en
# Microsoft FrontPage Server Extensions 2002
# Download the update: http://www.microsoft.com/downloads/details.aspx?FamilyId=3E8A21D9-708E-4E69-8299-86C49321EE25&displaylang=en
# Microsoft SharePoint Team Services 2002 (Shipped with Office XP)
# Download the update: http://www.microsoft.com/downloads/details.aspx?FamilyId=5923FC2F-D786-4E32-8F15-36A1C9E0A340&displaylang=en
#
# remote-MS03-051.nasl
#
# Author:
# Christian Eric Edjenguele <christian.edjenguele@owasp.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 or later,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###################################################################

CPE = "cpe:/a:microsoft:iis";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101012");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-03-16 00:04:04 +0100 (Mon, 16 Mar 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2003-0822", "CVE-2003-0824");
  script_name("Microsoft MS03-051 security check");
  script_category(ACT_ATTACK);
  script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_ms_iis_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("IIS/installed");

  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/MS03-051.mspx");

  script_tag(name:"solution", value:"Microsoft has released a patch to correct these issues.
  Please see the references for more information.

  Note: This update replaces the security updates contained in the following bulletins: MS01-035 and MS02-053.");

  script_tag(name:"summary", value:"The MS03-051 bulletin addresses two new security vulnerabilities in Microsoft FrontPage Server Extensions,
  the most serious of which could enable an attacker to run arbitrary code on a user's system.");

  script_tag(name:"insight", value:"The first vulnerability exists because of a buffer overrun in the remote debug functionality of FrontPage Server Extensions.

  This functionality enables users to remotely connect to a server running FrontPage Server Extensions and remotely debug content using, for example, Visual Interdev.
  An attacker who successfully exploited this vulnerability could be able to run code with IWAM_machinename account privileges on an affected system,
  or could cause FrontPage Server Extensions to fail.

  The second vulnerability is a Denial of Service vulnerability that exists in the SmartHTML interpreter.

  This functionality is made up of a variety of dynamic link library files, and exists to support certain types of dynamic web content.
  An attacker who successfully exploited this vulnerability could cause a server running Front Page Server Extensions to temporarily stop responding to requests.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port ) ) # To have a reference to the detection NVT
  exit( 0 );

hostname = http_host_name( port:port );

qry = string( 'POST ' + '/_vti_bin/_vti_aut/fp30reg.dll' + ' HTTP/1.0\r\n',
              'Connection: Keep-Alive\r\n',
              'Host: ' + hostname + '\r\n',
              'Transfer-Encoding:', ' chunked\r\n',
              '1\r\n\r\nX\r\n0\r\n\r\n');
reply = http_keepalive_send_recv( port:port, data:qry, bodyonly:FALSE );

if( egrep( pattern:"Microsoft-IIS/[45]\.[01]", string:reply, icase:TRUE ) ) {

  qry2 = string( 'POST ' + '/_vti_bin/_vti_aut/fp30reg.dll' + ' HTTP/1.0\r\n',
                 'Connection: Keep-Alive\r\n',
                 'Host: ' + hostname + '\r\n',
                 'Transfer-Encoding:', ' chunked\r\n',
                 '0\r\n\r\nX\r\n0\r\n\r\n');
  response = http_keepalive_send_recv( port:port, data:qry2, bodyonly:FALSE );

  if( egrep( pattern:"HTTP/1.[01] 200", string:response, icase:TRUE ) ) {
    security_message( port:port );
    exit( 0 );
  }
}

exit( 99 );