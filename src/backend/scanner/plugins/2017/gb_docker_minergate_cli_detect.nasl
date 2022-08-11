###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_docker_minergate_cli_detect.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# Docker is running minergate-cli Container
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140237");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 11874 $");

  script_name("Docker is running `minergate-cli` Container");

  script_tag(name:"summary", value:"The remote docker is running one or more `minergate-cli` container.");
  script_xref(name:"URL", value:"https://hub.docker.com/r/minecoins/minergate-cli/");

  script_tag(name:"vuldetect", value:"Check running containers.");
  script_tag(name:"solution_type", value:"Workaround");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-06 11:47:35 +0200 (Thu, 06 Apr 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_docker_remote_detect.nasl", "gb_docker_service_detection_lsc.nasl");
  script_mandatory_keys("docker/container/present");

  exit(0);
}

include("docker.inc");

if( ! c = docker_get_running_containers() ) exit( 0 );

foreach container ( c )
{
  if( container['image'] == "minecoins/minergate-cli" )
  {
    ac += 'ID:    ' + docker_truncate_id( container['id'] ) + '\n' +
          'Name:  ' + container['name'] + '\n' +
          'Image: ' + container['image'] + '\n\n';
  }
}

if( ac )
{
  report = 'The following `minecoins/minergate-cli` docker containers are running on the remote host:\n\n' + ac;
  security_message( port:0, data:report  );
  exit( 0 );
}

