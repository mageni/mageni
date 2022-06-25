###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_host_scanned_wmi.nasl 12724 2018-12-09 16:45:47Z cfischer $
#
# Leave information on scanned Windows hosts
#
# Authors:
# Thomas Rotter <thomas.rotter@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.96171");
  script_version("$Revision: 12724 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-12-09 17:45:47 +0100 (Sun, 09 Dec 2018) $");
  script_tag(name:"creation_date", value:"2013-03-03 10:37:58 +0100 (Sun, 03 Mar 2013)");
  script_name("Leave information on scanned Windows hosts");
  script_category(ACT_END);
  script_family("Windows");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_wmi_access.nasl", "host_scan_end.nasl");
  script_mandatory_keys("WMI/access_successful");

  script_add_preference(name:"Enable", type:"checkbox", value:"no");
  script_add_preference(name:"Message", type:"entry", value:"Security Scan of ::HOSTNAME:: finished. Start: ::SCAN_START:: Stop: ::SCAN_STOP::");

  script_tag(name:"summary", value:"This routine stores information about the scan on the scanned host,
  provided it is a Windows system remote registry and wmi access.

  The information cover hostname, scan start time and scan end time.
  No details about the actual scan results are stored on the scanned host.

  By default, this routine is disabled even it is selected to run. To activate
  it, it needs to be explicitly enabled with its corresponding preference switch.

  The preference 'Message' may contain 3 placeholder where respective content
  will be inserted into the message when the message is finally created on the
  target system:

  '::HOSTNAME::', '::SCAN_START::' and '::SCAN_STOP::'.

  At the end of the scan, the message will be written into the registry
  key 'SOFTWARE\VulScanInfo'.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("wmi_file.inc");
include("wmi_os.inc");
include("smb_nt.inc");

enabled = script_get_preference("Enable");
if ("yes" >!< enabled) exit(0);

infos = kb_smb_wmi_connectinfo();
if (!infos) exit(0);

handlereg = wmi_connect_reg(host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"]);
if(!handlereg){
  exit(0);
}

key = "SOFTWARE\VulScanInfo";

ex_str = "Scanstate";

function fancy_date() {
  local_var datestr;

  datestr =  _FCT_ANON_ARGS[0];
  if (int (datestr ) < 10) return string ("0", datestr);

  return datestr;
}

function make_date_str(date) {

  time = localtime(date);

  month  = fancy_date ( time["mon"]  );
  day    = fancy_date ( time["mday"] );
  hour   = fancy_date ( time["hour"] );
  minute = fancy_date ( time["min"]  );
  sec    = fancy_date ( time["sec"]  );

  return time["year"] +'-' + month + '-' + day + ' ' + hour + ':' + minute + ':' + sec;
}

function replace_placeholders(message) {

  local_var message;

  if("::HOSTNAME::" >< message)
    message = str_replace(string:message, find:"::HOSTNAME::",replace:get_host_name());

  if("::SCAN_START::" >< message) {

    start = get_kb_item("/tmp/start_time");

    if(start) {
      scan_start = make_date_str(date:start);
    } else {
      scan_start = 'Scan start unknown (ping_host.nasl not launched?)';
    }

    message = str_replace(string:message, find:"::SCAN_START::",replace:scan_start);
  }

  if("::SCAN_STOP::" >< message) {

    stop = get_kb_item("/tmp/stop_time");

    if(stop) {
      scan_stop = make_date_str(date:stop);
    } else { # if there is no stop time in kb, create it.
      scan_stop = make_date_str(date:unixtime());
    }

    message = str_replace(string:message, find:"::SCAN_STOP::",replace:scan_stop);
  }
  return message;
}

message = script_get_preference("Message");
if(strlen(message) < 1) {
  wmi_close(wmi_handle:handlereg);
  # Empty files are not possible. To simply create a file, the user needs to apply a dummy character like a white space.
  log_message(port:0, data:"No Message was given. Can not execute this test without a message.");
  exit(0);
}

message = replace_placeholders(message:message);

checkkey = wmi_reg_create_key(wmi_handle:handlereg, key:key);
if (!checkkey){
  wmi_close(wmi_handle:handlereg);
  log_message(port:0, data:"Error, can't set the Registry-Key.");
  exit(0);
}

checkstring = wmi_reg_set_ex_string_val(wmi_handle:handlereg, key:key, val_name:ex_str, val:message);
if (!checkstring){
  wmi_close(wmi_handle:handlereg);
  log_message(port:0, data:"Error, can't set the Registry-String");
  exit(0);
}

wmi_close(wmi_handle:handlereg);
log_message(port:0, data:"Registry-Key '" + key + "' with Message '" + message + "' successfully created.");
exit(0);