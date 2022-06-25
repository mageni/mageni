# OpenVAS Vulnerability Test
# Description: RedHat 6.0 cachemgr.cgi
#
# Authors:
# Alexis de Bernis <alexisb@cvs.nessus.org>
#
# Copyright:
# Copyright (C) 1999 A. de Bernis
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10034");
  script_version("2019-04-24T07:26:10+0000");
  script_tag(name:"last_modification", value:"2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(2059);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-1999-0710");
  script_name("RedHat 6.0 cachemgr.cgi");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 1999 A. de Bernis");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"If you are not using the box as a Squid www proxy/cache server then
  uninstall the package by executing:

  /etc/rc.d/init.d/squid stop, rpm -e squid

  If you want to continue using the Squid proxy server software, make the
  following actions to tighten security access to the manager interface:

  mkdir /home/httpd/protected-cgi-bin

  mv /home/httpd/cgi-bin/cachemgr.cgi /home/httpd/protected-cgi-bin/

  And add the following directives to /etc/httpd/conf/access.conf and
  srm.conf:

  --- start access.conf segment ---

  # Protected cgi-bin directory for programs that

  # should not have public access

  order deny, allow

  deny from all

  allow from localhost

  #allow from .your_domain.com

  AllowOverride None

  Options ExecCGI

  --- end access.conf segment ---

  --- start srm.conf segment ---

  ScriptAlias /protected-cgi-bin/ /home/httpd/protected-cgi-bin/

  --- end srm.conf segment ---");

  script_tag(name:"summary", value:"RedHat Linux 6.0 installs by default a squid cache manager cgi script with
  no restricted access permissions. This script could be used to perform a port scan from the cgi-host machine.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

cgi = "cachemgr.cgi";
res = is_cgi_installed_ka(item:cgi, port:port);
if(res) {
  security_message(port:port);
  exit(0);
}

exit(99);