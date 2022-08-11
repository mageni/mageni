<?php

namespace App\Http\Livewire\Classes;

use Carbon\Carbon;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;

/**
 * Schedule Class
 */
class Schedule
{
    protected $create_schedule;
    public $get_schedule_id;
    public $icalendar;

    /**
     * Create Schedule
     *
     * @param $name
     * @param $description
     * @param $timezone
     * @param $startdate
     * @param $frequency
     * @return mixed
     */
    public function create($description, $timezone, $startdate, $frequency, $recurrence = null)
    {
        $name = Str::uuid();
        $uuid = Str::uuid();

        /**
         * Carbon Now DTSTAMP
         */
        $getCarbon = Carbon::now();
        $obj = explode(" ", $getCarbon);

        $carb1 = date("Ymd", strtotime($obj[0]));
        $carb2 = date("Hi", strtotime($obj[1]));
        $carbonDate = $carb1."T".$carb2."00Z";

        /**
         * Schedule Start Time
         */
        $schStart = $startdate;
        $obj = explode(" ", $schStart);

        $sche = date("Ymd", strtotime($obj[0]));
        $hour = date("Hi", strtotime($obj[1]));
        $startTime = $sche."T".$hour."00Z";

        /**
         * iCalendar
         */
        $icalendar = "BEGIN:VCALENDAR\n";
        $icalendar .= "VERSION:2.0\n";
        $icalendar .= "PRODID:-//Mageni.net//NONSGML Mageni 1.1.0//EN\n";
        $icalendar .= "BEGIN:VEVENT\n";
        $icalendar .= "DTSTART:$startTime\n";
        $icalendar .= "DURATION:PT0S\n";
        if($frequency === 'ONCE') {
            $icalendar .= '';
        } elseif($frequency === 'WORKWEEK') {
            $icalendar .= "RRULE:FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR\n";
        } elseif($frequency) {
            $icalendar .= "RRULE:FREQ=$frequency\n";
        }
        $icalendar .= "UID:$uuid\n";
        $icalendar .= "DTSTAMP:$carbonDate\n";
        $icalendar .= "END:VEVENT\n";
        $icalendar .= "END:VCALENDAR\n";

        /**
         * Request
         */
        $this->create_schedule = "<create_schedule>";
        $this->create_schedule .= "<name>$name</name>";
        $this->create_schedule .= "<comment>$description</comment>";
        $this->create_schedule .= "<icalendar>$icalendar</icalendar>";
        $this->create_schedule .= "<timezone>$timezone</timezone>";
        $this->create_schedule .= "</create_schedule>";

        /**
         * Connect to Socket
         */
        $socket = new Socket();

        Log::info('Processing Schedule Creation');

        return $this->get_schedule_id = $socket->createSchedule($this->create_schedule);
    }

    /**
     * Modify Schedule
     *
     * @param $name
     * @param $description
     * @param $timezone
     * @param $startdate
     * @param $frequency
     * @return mixed
     */
    public function modify($id, $description, $timezone, $startdate, $frequency)
    {
        $name = Str::uuid();
        $uuid = Str::uuid();

        /**
         * Carbon Now DTSTAMP
         */
        $getCarbon = Carbon::now();
        $obj = explode(" ", $getCarbon);

        $carb1 = date("Ymd", strtotime($obj[0]));
        $carb2 = date("Hi", strtotime($obj[1]));
        $carbonDate = $carb1."T".$carb2."00Z";

        /**
         * Schedule Start Time
         */
        $schStart = $startdate;
        $obj = explode(" ", $schStart);

        $sche = date("Ymd", strtotime($obj[0]));
        $hour = date("Hi", strtotime($obj[1]));
        $startTime = $sche."T".$hour."00Z";

        /**
         * iCalendar
         */
        $icalendar = "BEGIN:VCALENDAR\n";
        $icalendar .= "VERSION:2.0\n";
        $icalendar .= "PRODID:-//Mageni.net//NONSGML Mageni 1.1.0//EN\n";
        $icalendar .= "BEGIN:VEVENT\n";
        $icalendar .= "DTSTART:$startTime\n";
        $icalendar .= "DURATION:PT0S\n";
        if($frequency === 'ONCE') {
            $icalendar .= '';
        } elseif($frequency === 'WORKWEEK') {
            $icalendar .= "RRULE:FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR\n";
        } elseif($frequency) {
            $icalendar .= "RRULE:FREQ=$frequency\n";
        }
        $icalendar .= "UID:$uuid\n";
        $icalendar .= "DTSTAMP:$carbonDate\n";
        $icalendar .= "END:VEVENT\n";
        $icalendar .= "END:VCALENDAR\n";

        /**
         * Request
         */
        $this->create_schedule = "<modify_schedule schedule_id='$id'>";
        $this->create_schedule .= "<name>$name</name>";
        $this->create_schedule .= "<comment>$description</comment>";
        $this->create_schedule .= "<icalendar>$icalendar</icalendar>";
        $this->create_schedule .= "<timezone>$timezone</timezone>";
        $this->create_schedule .= "</modify_schedule>";

        /**
         * Connect to Socket
         */
        $socket = new Socket();

        Log::info('Processing Schedule Modification');

        return $this->get_schedule_id = $socket->modifySchedule($this->create_schedule, $id);
    }

    public function delete($id)
    {
        $socket = new Socket();

        Log::info('Processing Schedule Deletion');

        $this->request = "<delete_schedule schedule_id='$id' ultimate='1'/>";

        return $this->get_delete_result = $socket->deleteSchedule($this->request, $id);
    }
}

