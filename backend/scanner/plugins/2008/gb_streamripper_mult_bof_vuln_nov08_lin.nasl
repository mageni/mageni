###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_streamripper_mult_bof_vuln_nov08_lin.nasl 12722 2018-12-08 15:39:45Z cfischer $
#
# Streamripper Multiple Buffer Overflow Vulnerabilities (Linux)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.800147");
  script_version("$Revision: 12722 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-08 16:39:45 +0100 (Sat, 08 Dec 2018) $");
  script_tag(name:"creation_date", value:"2008-12-01 15:31:19 +0100 (Mon, 01 Dec 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-4829");
  script_bugtraq_id(32356);
  script_name("Streamripper Multiple Buffer Overflow Vulnerabilities (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_mandatory_keys("login/SSH/success");
  script_dependencies("gather-package-list.nasl");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"http://secunia.com/advisories/32562");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/3207");

  script_tag(name:"impact", value:"Successful attack could lead to execution of arbitrary code by tricking a
  user into connecting to a malicious server or can even cause denial of
  service condition.");

  script_tag(name:"affected", value:"Streamripper Version 1.63.5 and earlier on Linux.");

  script_tag(name:"insight", value:"The flaws are due to boundary error within,

  - http_parse_sc_header() function in lib/http.c, when parsing an overly long
    HTTP header starting with Zwitterion v.

  - http_get_pls() and http_get_m3u() functions in lib/http.c, when parsing a
    specially crafted pls playlist containing an overly long entry or m3u
    playlist containing an overly long File entry.");

  script_tag(name:"solution", value:"Upgrade to Version 1.64.0 or later.");

  script_tag(name:"summary", value:"The host is installed with Streamripper, which is prone to Multiple
  Buffer Overflow Vulnerabilities.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

binPaths = find_bin(prog_name:"streamripper", sock:sock);
if(!binPaths){
  ssh_close_connection();
  exit(0);
}

foreach srBin(binPaths){

  srBin = chomp(srBin);
  if(!srBin) continue;

  srVer = get_bin_version(full_prog_name:srBin, version_argv:"-v", ver_pattern:"Streamripper ([0-9.]+)", sock:sock);
  if(srVer[1]){
    if(version_is_less(version:srVer[1], test_version:"1.64.0")){
      report = report_fixed_ver(installed_version:srVer[1], fixed_version:"1.64.0", install_path:srBin);
      security_message(port:0, data:report);
      ssh_close_connection();
      exit(0);
    }
  }
}

ssh_close_connection();
exit(0);