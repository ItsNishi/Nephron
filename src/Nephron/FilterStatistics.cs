namespace Nephron;

/// <summary>Thread-safe scan counters for one <see cref="NephronFilter"/>.</summary>
public sealed class FilterStatistics
{
	private long _Total_Scans;
	private long _Total_Allowed;
	private long _Total_Flagged;
	private long _Total_Blocked;
	private long _Total_Detections;

	public long TotalScans => Interlocked.Read(ref _Total_Scans);

	public long TotalAllowed => Interlocked.Read(ref _Total_Allowed);

	public long TotalFlagged => Interlocked.Read(ref _Total_Flagged);

	public long TotalBlocked => Interlocked.Read(ref _Total_Blocked);

	public long TotalDetections => Interlocked.Read(ref _Total_Detections);

	internal void Record(Verdict verdict, int detection_count)
	{
		Interlocked.Increment(ref _Total_Scans);
		Interlocked.Add(ref _Total_Detections, detection_count);
		switch (verdict)
		{
			case Verdict.Allow:
				Interlocked.Increment(ref _Total_Allowed);
				break;
			case Verdict.Flag:
				Interlocked.Increment(ref _Total_Flagged);
				break;
			case Verdict.Block:
				Interlocked.Increment(ref _Total_Blocked);
				break;
		}
	}

	/// <summary>Zeroes every counter.</summary>
	public void Reset()
	{
		Interlocked.Exchange(ref _Total_Scans, 0);
		Interlocked.Exchange(ref _Total_Allowed, 0);
		Interlocked.Exchange(ref _Total_Flagged, 0);
		Interlocked.Exchange(ref _Total_Blocked, 0);
		Interlocked.Exchange(ref _Total_Detections, 0);
	}
}
