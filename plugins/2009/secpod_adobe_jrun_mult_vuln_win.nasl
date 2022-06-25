###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_jrun_mult_vuln_win.nasl 12602 2018-11-30 14:36:58Z cfischer $
#
# Adobe JRun Management Console Multiple Vulnerabilities (Windows)
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900823");
  script_version("$Revision: 12602 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-30 15:36:58 +0100 (Fri, 30 Nov 2018) $");
  script_tag(name:"creation_date", value:"2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-1873", "CVE-2009-1874");
  script_bugtraq_id(36047, 36050);
  script_name("Adobe JRun Management Console Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_adobe_jrun_detect.nasl", "smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("/Adobe/JRun/Ver", "SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause XSS attacks or
  Directory Traversal attack using the affected application.");

  script_tag(name:"affected", value:"Adobe JRun version 4.0 on Windows");

  script_tag(name:"insight", value:"- Multiple XSS vulnerabilities exists due to error in the Management
  Console which can be exploited to inject arbitrary web script or HTML via unspecified vectors.

  - A Directory traversal attack is possible due to error in logging/logviewer.jsp in the Management Console
  which can be exploited by authenticated users to read arbitrary files via a .. (dot dot) in the logfile parameter.");

  script_tag(name:"summary", value:"The host is running Adobe JRun and is prone to multiple vulnerabilities.");

  script_tag(name:"solution", value:"Apply the security updates from the referenced advisories.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://download.macromedia.com/pub/coldfusion/updates/jmc-app.ear");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36329/");
  script_xref(name:"URL", value:"http://www.dsecrg.com/pages/vul/show.php?id=151");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb09-12.html");

  exit(0);
}

include("smb_nt.inc");
include("http_func.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

jrunVer = get_kb_item("/Adobe/JRun/Ver");

if(jrunVer =~ "^4")
{
  if(!get_kb_item("SMB/WindowsVersion")){
    exit(0);
  }

  jrunFile = registry_get_sz(key:"SOFTWARE\Macromedia\Install Data\JRun 4",
                            item:"INSTALLDIR");
  jrunFile += "\bin\jrun.exe";
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:jrunFile);
  jrun = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:jrunFile);
  jrunVer = GetVer(file:jrun, share:share);

  if(version_in_range(version:jrunVer, test_version:"4.0",
                                      test_version2:"4.0.7.43085")){
    security_message(port:0);
  }
}
