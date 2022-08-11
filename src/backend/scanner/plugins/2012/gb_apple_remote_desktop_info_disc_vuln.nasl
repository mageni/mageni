###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_remote_desktop_info_disc_vuln.nasl 14307 2019-03-19 10:09:27Z cfischer $
#
# Apple Remote Desktop Information Disclosure Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802964");
  script_version("$Revision: 14307 $");
  script_cve_id("CVE-2012-0681");
  script_bugtraq_id(55100);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 11:09:27 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-09-25 18:02:57 +0530 (Tue, 25 Sep 2012)");
  script_name("Apple Remote Desktop Information Disclosure Vulnerability");
  script_xref(name:"URL", value:"http://support.apple.com/kb/HT5462");
  script_xref(name:"URL", value:"http://support.apple.com/downloads");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50352");
  script_xref(name:"URL", value:"http://lists.apple.com/archives/security-announce/2012/Sep/msg00002.html");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to gain sensitive information.");
  script_tag(name:"affected", value:"Apple Remote Desktop version 3.5.2");
  script_tag(name:"insight", value:"The flaw is due to an error in application, when connecting to a
  third-party VNC server with 'Encrypt all network data' set, data is not
  encrypted and no warning is produced.");
  script_tag(name:"solution", value:"Upgrade to Apple Remote Desktop version 3.5.3 or later.");
  script_tag(name:"summary", value:"This host is installed with Apple Remote Desktop and is prone to
  information disclosure vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

if(!get_kb_item("ssh/login/osx_name")) {
  close(sock);
  exit(0);
}

rdVer = chomp(ssh_cmd(socket:sock, cmd:"defaults read /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Info CFBundleShortVersionString"));
close(sock);

if(!rdVer || rdVer !~ "^[0-3]\." || "does not exist" >< rdVer){
  exit(0);
}

## Apple Remote Desktop version 3.5.2
if(version_is_less_equal(version:rdVer, test_version:"3.5.2")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
