###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_libcloud_ssl_cert_sec_bypass_vuln.nasl 11987 2018-10-19 11:05:52Z mmartin $
#
# Libcloud SSL Certificates Security Bypass Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802164");
  script_version("$Revision: 11987 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 13:05:52 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-09-22 10:24:03 +0200 (Thu, 22 Sep 2011)");
  script_cve_id("CVE-2010-4340");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Libcloud SSL Certificates Security Bypass Vulnerability");
  script_xref(name:"URL", value:"http://wiki.apache.org/incubator/LibcloudSSL");
  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/LIBCLOUD-55");
  script_xref(name:"URL", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=598463");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to spoof certificates and
  bypass intended access restrictions via a man-in-the-middle (MITM) attack.");
  script_tag(name:"affected", value:"libcloud version prior to 0.4.1");
  script_tag(name:"insight", value:"The flaw is due to improper verification of SSL certificates for
  HTTPS connections.");
  script_tag(name:"solution", value:"Upgrade to  libcloud version 0.4.1 or later");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is installed with Libcloud and is prone to security
  bypass vulnerability.");
  script_xref(name:"URL", value:"http://libcloud.apache.org/");
  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

libName = find_file(file_name:"__init__.py", file_path:"/libcloud/",
                            useregex:TRUE, regexpar:"$", sock:sock);

if(libName)
{
  foreach binaryName (libName)
  {
    libVer = get_bin_version(full_prog_name:"cat", sock:sock,
                             version_argv:chomp(binaryName),
                             ver_pattern:"= '([0-9.]+)'");
    if(libVer[1])
    {
      if(version_is_less(version:libVer[1], test_version:"0.4.1"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        close(sock);
        exit(0);
      }
    }
  }
}
close(sock);
