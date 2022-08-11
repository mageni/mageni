###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_libtiff_buf_vuln.nasl 12725 2018-12-09 17:18:10Z cfischer $
#
# LibTIFF TIFF Image Buffer Underflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800646");
  script_version("$Revision: 12725 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-09 18:18:10 +0100 (Sun, 09 Dec 2018) $");
  script_tag(name:"creation_date", value:"2009-07-07 11:58:41 +0200 (Tue, 07 Jul 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-2285");
  script_bugtraq_id(35451);
  script_name("LibTIFF TIFF Image Buffer Underflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35515/");
  script_xref(name:"URL", value:"https://bugs.edge.launchpad.net/bugs/380149");
  script_xref(name:"URL", value:"http://www.lan.st/showthread.php?t=1856&page=3");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1637");
  script_xref(name:"URL", value:"http://bugzilla.maptools.org/attachment.cgi?id=314");

  script_tag(name:"affected", value:"LibTIFF versions 3.x");

  script_tag(name:"insight", value:"The flaw is due to buffer underflow error in the 'LZWDecodeCompat()'
  [libtiff/tif_lzw.c] function when processing malicious TIFF images.");

  script_tag(name:"solution", value:"Apply the patches available from the linked references.");

  script_tag(name:"summary", value:"This host is installed with LibTIFF and is prone to buffer
  underflow vulnerability.");

  script_tag(name:"impact", value:"A remote attacker could exploit this issue to execute arbitrary code
  or to crash the affected application.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock) exit(0);

libtiffPaths = find_file(file_name:"config.status", file_path:"/", useregex:TRUE, regexpar:"$", sock:sock);
if(!libtiffPaths){
  ssh_close_connection();
  exit(0);
}

foreach libtiffBin(libtiffPaths) {

  libtiffBin = chomp(libtiffBin);
  if(!libtiffBin) continue;

  libtiffVer = get_bin_version(full_prog_name:libtiffBin, sock:sock, version_argv:"--version", ver_pattern:"config.status ([0-9.]+)");

  if("LibTIFF" >< libtiffVer && libtiffVer[1]) {
    if(version_in_range(version:libtiffVer[1], test_version:"3.0", test_version2:"3.8.2")){
      report = report_fixed_ver(installed_version:libtiffVer[1], fixed_version:"See references", install_path:libtiffBin);
      security_message(port:0, data:report);
      ssh_close_connection();
      exit(0);
    }
  }
}

ssh_close_connection();
exit(0);