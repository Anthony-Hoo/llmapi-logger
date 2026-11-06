package orgreport

import (
	"errors"
	"time"
)

// WeekLayout is the wire format of a week: the local date its first day.
const WeekLayout = "2006-01-02"

// WeekStartOf returns the local midnight that starts the week containing t.
func WeekStartOf(t time.Time, location *time.Location, weekStart time.Weekday) time.Time {
	local := t.In(location)
	offset := (int(local.Weekday()) - int(weekStart) + 7) % 7
	day := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, location)
	return day.AddDate(0, 0, -offset)
}

// Week is a half-open local week [Start, End). End is seven local days later,
// so a daylight-saving week is 167 or 169 hours long.
type Week struct {
	Start time.Time
	End   time.Time
}

// Label returns the week's wire form.
func (week Week) Label() string { return week.Start.Format(WeekLayout) }

// Days returns the seven local day boundaries plus the end, eight values.
func (week Week) Days() []time.Time {
	days := make([]time.Time, 0, 8)
	for index := 0; index <= 7; index++ {
		days = append(days, week.Start.AddDate(0, 0, index))
	}
	return days
}

// WeekOf returns the week containing t.
func (settings Settings) WeekOf(t time.Time) Week {
	start := WeekStartOf(t, settings.Location, settings.WeekStart)
	return Week{Start: start, End: start.AddDate(0, 0, 7)}
}

// ParseWeek accepts a local date that must be the first day of a week.
func (settings Settings) ParseWeek(label string) (Week, error) {
	day, err := time.ParseInLocation(WeekLayout, label, settings.Location)
	if err != nil {
		return Week{}, errors.New("orgreport: week must be a YYYY-MM-DD date")
	}
	week := settings.WeekOf(day)
	if !week.Start.Equal(day) {
		return Week{}, errors.New("orgreport: week must name the first day of a report week")
	}
	return week, nil
}

// Previous returns the week before.
func (week Week) Previous() Week {
	start := week.Start.AddDate(0, 0, -7)
	return Week{Start: start, End: week.Start}
}
