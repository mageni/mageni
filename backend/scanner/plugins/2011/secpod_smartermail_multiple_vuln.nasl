###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_smartermail_multiple_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# SmarterMail Multiple Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = 'cpe:/a:smartertools:smartermail';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901196");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-03-25 15:52:06 +0100 (Fri, 25 Mar 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("SmarterMail Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/41677/");
  script_xref(name:"URL", value:"http://secunia.com/advisories/41485/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16955/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/99169/smartermail-xsstraversalshell.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_smartermail_detect.nasl");
  script_require_ports("Services/www", 80, 9998);
  script_mandatory_keys("SmarterMail/installed");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to conduct cross site scripting,
  shell upload and directory traversal attacks.");
  script_tag(name:"affected", value:"SmarterTools SmarterMail versions 7.4 and prior.");
  script_tag(name:"insight", value:"Input passed in the 'path' parameter to Main/frmStoredFiles.aspx, the 'edit'
  parameter to UserControls/Popups/frmAddFileStorageFolder.aspx, the
  'SubjectBox_SettingText' parameter to Main/Calendar/frmEvent.aspx, the 'url'
  parameter to UserControls/Popups/frmHelp.aspx, the 'folder' parameter to
  UserControls/Popups/frmDeleteConfirm.aspx, the 'editfolder' parameter to
  UserControls/Popups/frmEventGroup.aspx, the 'deletefolder' parameter to
  UserControls/Popups/frmEventGroup.aspx, and the 'bygroup' parameter to
  Main/Alerts/frmAlerts.aspx is not properly sanitised before being returned
  to the user.");
  script_tag(name:"solution", value:"Upgrade to SmarterTools SmarterMail 8.0 or later.");
  script_tag(name:"summary", value:"This host is running SmarterMail and is prone to multiple
  vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.smartertools.com/smartermail/mail-server-software.aspx");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"7.0", test_version2:"7.4" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"8.0" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );