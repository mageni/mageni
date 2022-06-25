###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openvas_manager_command_exec_vuln.nasl 12076 2018-10-25 08:39:24Z cfischer $
#
# OpenVAS Manager OMP Request Handling Command Injection Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801920");
  script_version("$Revision: 12076 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 10:39:24 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)");
  script_cve_id("CVE-2011-0018");
  script_bugtraq_id(45987);
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_name("OpenVAS Manager OMP Request Handling Command Injection Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/43037");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/65011");
  script_xref(name:"URL", value:"http://www.openvas.org/OVSA20110118.html");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/16086/");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2011/0208");
  script_xref(name:"URL", value:"http://www.openvas.org/");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary commands
  with the privileges of the OpenVAS Manager (typically root).");

  script_tag(name:"affected", value:"OpenVAS Manager versions prior to 1.0.4 and prior to 2.0.2");

  script_tag(name:"insight", value:"The flaw is due to an input validation error in the 'email()' function
  in 'manage_sql.c' while processing OMP (OpenVAS Management Protocol) requests
  sent by authenticated users of the GSA (Greenbone Security Assistant) web application.");

  script_tag(name:"summary", value:"This host is installed with OpenVAS Manager and is prone command
  injection vulnerability.");

  script_tag(name:"solution", value:"Apply the patch or upgrade to OpenVAS Manager 1.0.4, 2.0.2 or later.

  *****

  NOTE : Ignore this warning, if above mentioned patch is already applied.

  *****");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

paths = find_bin(prog_name:"openvasmd", sock:sock);
foreach stardictbin (paths)
{
  omVer = get_bin_version(full_prog_name:chomp(stardictbin),
                          sock:sock, version_argv:"--version",
                          ver_pattern:"OpenVAS Manager.*");

  if(omVer[0] != NULL)
  {
    omVer = eregmatch(pattern:"OpenVAS Manager ([0-9]\.[0-9]\.[0-9]+).?(rc[0-9]+)?",
                      string:omVer[0]);
    if(omVer[1] != NULL && omVer[2] != NULL)
    {
      ver = omVer[1] + "." + omVer[2];
    }
    else if(omVer [1]!= NULL  && omVer[2] == NULL){
      ver =omVer[1];
    }
  }

  if(ver)
  {
    if(version_in_range(version:ver, test_version:"1.0", test_version2:"1.0.3") ||
       version_in_range(version:ver, test_version:"2.0", test_version2:"2.0.1"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      close(sock);
      exit(0);
    }
  }
}
close(sock);
ssh_close_connection();
