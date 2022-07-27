###############################################################################
# OpenVAS Vulnerability Test
# $Id: cgi_directories.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# CGI Scanning Consolidation
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.111038");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-09-14 07:00:00 +0200 (Mon, 14 Sep 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("CGI Scanning Consolidation");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_twonky_server_detect.nasl",
  "gb_owncloud_detect.nasl", "gb_adobe_aem_remote_detect.nasl", "gb_libreoffice_online_detect.nasl",
  "gb_apache_activemq_detect.nasl", "gb_orientdb_server_detect.nasl"); # gb_* are additional dependencies setting auth_required
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"https://www.mageni.net");

  script_add_preference(name:"Maximum number of items shown for each list", type:"entry", value:"100");

  script_tag(name:"summary", value:"The script consolidates various information for CGI scanning.

  This information is based on the following scripts / settings:

  - HTTP-Version Detection (OID: 1.3.6.1.4.1.25623.1.0.100034)

  - No 404 check (OID: 1.3.6.1.4.1.25623.1.0.10386)

  - Web mirroring / webmirror.nasl (OID: 1.3.6.1.4.1.25623.1.0.10662)

  - Directory Scanner / DDI_Directory_Scanner.nasl (OID: 1.3.6.1.4.1.25623.1.0.11032)

  - The configured 'cgi_path' within the 'Scanner Preferences' of the scan config in use

  - The configured 'Enable CGI scanning', 'Enable generic web application scanning' and
    'Add historic /scripts and /cgi-bin to directories for CGI scanning' within the
    'Global variable settings' of the scan config in use

  If you think any of this information is wrong please report it to the help@mageni.net");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit( 66 );