from pydub.generators import Sine

# Generate a 1-second 440Hz sine wave
tone = Sine(440).to_audio_segment(duration=1000)

# Save it as an alert sound
tone.export("alert_sound.wav", format="wav")

print("Alert sound generated: alert_sound.wav")
