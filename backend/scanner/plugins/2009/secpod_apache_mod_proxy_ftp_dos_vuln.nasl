###############################################################################
# OpenVAS Vulnerability Test
#
# Apache 'mod_proxy_ftp' Module Denial Of Service Vulnerability (Linux)
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
  script_oid("1.3.6.1.4.1.25623.1.0.900841");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2009-09-16 15:34:19 +0200 (Wed, 16 Sep 2009)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_cve_id("CVE-2009-3094");
  script_bugtraq_id(36260);
  script_name("Apache 'mod_proxy_ftp' Module Denial Of Service Vulnerability (Linux)");
  script_xref(name:"URL", value:"http://intevydis.com/vd-list.shtml");
  script_xref(name:"URL", value:"http://www.intevydis.com/blog/?p=59");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36549");
  script_xref(name:"URL", value:"http://httpd.apache.org/docs/2.0/mod/mod_proxy_ftp.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("apache/banner");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause a Denial of
  Service in the context of the affected application.");

  script_tag(name:"affected", value:"Apache HTTP Server version 2.0.x to 2.0.63 and and 2.2.x to 2.2.13 on Linux.");

  script_tag(name:"insight", value:"The flaw is due to an error in 'ap_proxy_ftp_handler' function in
  modules/proxy/proxy_ftp.c in the mod_proxy_ftp module while processing
  responses received from FTP servers. This can be exploited to trigger a
  NULL-pointer dereference and crash an Apache child process via a malformed EPSV response.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to Apache HTTP Server version 2.2.15 or later.");

  script_tag(name:"summary", value:"The host is running Apache and is prone to Denial of Service
  vulnerability.");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");

apachePort = get_http_port(default:80);
banner = get_http_banner(port:apachePort);
if(!banner)
  exit(0);

if(banner =~ "Apache/([0-9.]+) \(Win32\)")
  exit(0);

apacheVer = eregmatch(pattern:"Server: Apache/([0-9.]+)", string:banner);

if(!isnull(apacheVer[1]))
{
  if(version_in_range(version:apacheVer[1], test_version:"2.0.0", test_version2:"2.0.63")||
     version_in_range(version:apacheVer[1], test_version:"2.2.0", test_version2:"2.2.13")){
    security_message(apachePort);
  }
}
