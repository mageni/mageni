###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_chasen_bof_vuln_lin.nasl 12010 2018-10-22 08:23:57Z mmartin $
#
# ChaSen Buffer Overflow Vulnerability (Linux)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
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
  script_oid("1.3.6.1.4.1.25623.1.0.802344");
  script_version("$Revision: 12010 $");
  script_cve_id("CVE-2011-4000");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 10:23:57 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-11-11 14:20:07 +0530 (Fri, 11 Nov 2011)");
  script_name("ChaSen Buffer Overflow Vulnerability (Linux)");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN16901583/index.html");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2011/JVNDB-2011-000099.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to cause a buffer overflow
  or execute arbitrary code.");
  script_tag(name:"affected", value:"ChaSen Version 2.4.x");
  script_tag(name:"insight", value:"The flaw is due to an error when reading user-supplied input string,
  which allows attackers to execute arbitrary code via a crafted string.");
  script_tag(name:"solution", value:"Use ChaSen Version 2.3.3.");
  script_tag(name:"summary", value:"The host is running ChaSen Software and is prone to buffer
  overflow vulnerability");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://chasen.naist.jp/hiki/ChaSen/");
  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

chaName = find_file(file_name:"chasen-config", file_path:"/", useregex:TRUE,
                         regexpar:"$", sock:sock);

foreach binaryName (chaName)
{
  chaVer = get_bin_version(full_prog_name:chomp(binaryName), version_argv:"--version",
                             ver_pattern:"[0-9.]+", sock:sock);

  if(chaVer[1] != NULL)
  {
    if(version_in_range(version:chaVer[1], test_version:"2.4.0", test_version2:"2.4.4"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      close(sock);
      exit(0);
    }
  }
}
close(sock);
