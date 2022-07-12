# Copyright (C) 2015 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806723");
  script_version("2021-03-04T06:06:57+0000");
  script_tag(name:"last_modification", value:"2021-03-11 11:26:33 +0000 (Thu, 11 Mar 2021)");
  script_tag(name:"creation_date", value:"2015-11-24 16:05:56 +0530 (Tue, 24 Nov 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("OpenSSL Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("OpenSSL/banner");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"HTTP based detection of OpenSSL.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

banner = http_get_remote_headers(port: port);

if (banner && concl = egrep(string: banner, pattern: "^Server\s*:.*OpenSSL", icase: TRUE)) {
  version = "unknown";
  concl = chomp(concl);

  vers = eregmatch(pattern: 'OpenSSL/([0-9]+[^ \r\n]+)', string: banner, icase: TRUE);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "openssl/detected", value: TRUE);
  set_kb_item(name: "openssl_or_gnutls/detected", value: TRUE);
  set_kb_item(name: "openssl/http/detected", value: TRUE);

  set_kb_item(name: "openssl/http/" + port + "/installs",
              value: port + "#---#" + port + "/tcp#---#" + version + "#---#" + concl);
}

exit(0);
