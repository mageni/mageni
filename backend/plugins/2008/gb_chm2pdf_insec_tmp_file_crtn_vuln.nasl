###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_chm2pdf_insec_tmp_file_crtn_vuln.nasl 12725 2018-12-09 17:18:10Z cfischer $
#
# chm2pdf Insecure Temporary File Creation or DoS Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800316");
  script_version("$Revision: 12725 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-09 18:18:10 +0100 (Sun, 09 Dec 2018) $");
  script_tag(name:"creation_date", value:"2008-12-12 16:11:26 +0100 (Fri, 12 Dec 2008)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5298", "CVE-2008-5299");
  script_bugtraq_id(31735);
  script_name("chm2pdf Insecure Temporary File Creation or DoS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux"); # Only Debian is affected

  script_xref(name:"URL", value:"http://secunia.com/advisories/32257/");
  script_xref(name:"URL", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=501959");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2008/12/01/5");
  script_xref(name:"URL", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?msg=20;filename=chm2pdf_nmu.diff;att=1;bug=501959");

  script_tag(name:"impact", value:"Successful exploitation will allow local users to delete arbitrary files
  via symlink attack or corrupt sensitive files, which may also result in a denial of service.");

  script_tag(name:"affected", value:"chm2pdf version prior to 0.9.1 on Debian");

  script_tag(name:"insight", value:"The vulnerability is due to following,

  - error in .chm file in /tmp/chm2pdf/orig and /tmp/chm2pdf/work temporary
    directories.

  - uses temporary files in directories with fixed names.");

  script_tag(name:"summary", value:"This host is installed with chm2pdf and is prone to Insecure
  Temporary File Creation or Denial of Service Vulnerability.");

  script_tag(name:"solution", value:"Upgrade to a later higher version or apply the patche from
  the referenced link.");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

binPaths = find_file(file_name:"chm2pdf", file_path:"/", useregex:TRUE, regexpar:"$", sock:sock);
if(!binPaths){
  ssh_close_connection();
  exit(0);
}

foreach c2pBin(binPaths){

  c2pBin = chomp(c2pBin);
  if(!c2pBin) continue;

  c2pVer = get_bin_version(full_prog_name:c2pBin, version_argv:"--version", ver_pattern:"version ([0-9.]+)", sock:sock);
  if(c2pVer[1]){
    if(version_is_less(version:c2pVer[1], test_version:"0.9.1")){
      report = report_fixed_ver(installed_version:c2pVer[1], fixed_version:"0.9.1", install_path:c2pBin);
      security_message(port:0, data:report);
      ssh_close_connection();
      exit(0);
    }
  }
}

ssh_close_connection();
exit(0);