###############################################################################
# OpenVAS Vulnerability Test
#
# Mojolicious Directory Traversal Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801882");
  script_version("2019-05-17T12:32:34+0000");
  script_tag(name:"last_modification", value:"2019-05-17 12:32:34 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2011-05-18 15:37:30 +0200 (Wed, 18 May 2011)");
  script_bugtraq_id(47402);
  script_cve_id("CVE-2011-1589");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Mojolicious Directory Traversal Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/44051");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/66830");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=697229");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_mandatory_keys("Mojolicious/banner");
  script_require_ports("Services/www", 3000);

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain sensitive information
  that could aid in further attacks.");

  script_tag(name:"affected", value:"Mojolicious versions prior to 1.16.");

  script_tag(name:"insight", value:"The flaw is due to an error in 'Path.pm', which allows remote
  attackers to read arbitrary files via a %2f..%2f (encoded slash dot dot slash) in a URI.");

  script_tag(name:"solution", value:"Upgrade to Mojolicious version 1.16 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"The host is running Mojolicious and is prone to directory traversal
  vulnerability.");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port(default:3000);

banner = get_http_banner(port:port);

if("Server: Mojolicious" >< banner)
{
  files = traversal_files();
  foreach file (keys(files))
  {
    url = string(crap(data:"..%2f",length:5*10),files[file]);

    if(http_vuln_check(port:port, url:url, pattern:file)) {
      report = report_vuln_url(port:port, url:url);
      security_message(port:port, data:report);
    }
  }
}
