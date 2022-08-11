##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_policy_docker_skipped.nasl 11532 2018-09-21 19:07:30Z cfischer $
#
# Docker Compliance Check: Skipped
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
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.140125");
  script_version("$Revision: 11532 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-21 21:07:30 +0200 (Fri, 21 Sep 2018) $");
  script_tag(name:"creation_date", value:"2017-01-19 11:24:37 +0100 (Thu, 19 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod", value:"98");

  script_name("Docker Compliance Check: Skipped");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Policy");
  script_dependencies("Policy/gb_policy_docker.nasl");
  script_mandatory_keys("docker/docker_test/has_skipped_tests", "docker/docker_test/report_skipped");

  script_tag(name:"summary", value:"Lists all the Docker Compliance Policy Checks errors.");

  exit(0);
}

include("misc_func.inc");
include("docker.inc");
include("docker_policy.inc");
include("docker_policy_tests.inc");

if( ! f = get_kb_list("docker/docker_test/skipped/*") ) exit( 0 );

skipped_count = max_index( keys( f ) );

if( skipped_count == 0 )
  exit( 0 );

report = skipped_count + ' Checks skipped:\n\n';

foreach skipped ( sort( keys( f ) ) )
{
  _id = eregmatch( pattern:'docker/docker_test/skipped/([0-9.]+)', string:skipped );

  if( isnull( _id[1] ) )
    continue;

  id = _id[1];
  reason = chomp( f[ skipped ] );

  data = get_docker_test_data( id:id );

  report += ' - ' + data['title'] + '\n\nResult: ' + reason + '\n\n';
}

log_message( port:0, data:report );

exit( 0 );

