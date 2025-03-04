package gsharp

import (
	"database/sql/driver"
	"time"
)

type DataTime time.Time

type DateFormatType string

const (
	Date            DateFormatType = "2006-01-02"
	DateSecond      DateFormatType = "2006-01-02 15:04:05"
	DateMillisecond DateFormatType = "2006-01-02 15:04:05.000"
)

func (t *DataTime) UnmarshalJSON(data []byte) (err error) {
	if string(data) == "null" {
		return nil
	}
	now, err := time.ParseInLocation(string(`"`+DateSecond+`"`), string(data), time.Local)
	*t = DataTime(now)
	return
}

func (t DataTime) MarshalJSON() ([]byte, error) {
	b := make([]byte, 0, len(DateSecond)+2)
	b = append(b, '"')
	b = time.Time(t).AppendFormat(b, string(DateSecond))
	b = append(b, '"')
	return b, nil
}

func (t DataTime) String() string {
	return time.Time(t).Format(string(DateSecond))
}

func (t DataTime) Value() (driver.Value, error) {
	return time.Time(t).Format(string(DateSecond)), nil
}

func (t DataTime) ToString(format DateFormatType) string {
	return time.Time(t).Format(string(format))
}

func (t DataTime) ToTime(format DateFormatType) time.Time {
	parse, err := time.ParseInLocation(string(format), t.ToString(format), time.Local)
	if err != nil {
		return time.Time(t)
	}
	return parse
}
