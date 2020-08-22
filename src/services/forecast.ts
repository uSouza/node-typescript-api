import { StormGlass, ForecastPoint } from '@src/clients/stormGlass';
import { InternalError } from '@src/util/errors/internal-error';
import { Beach } from '@src/models/beach';

export interface TimeForecast {
  time: string;
  forecast: BeachForecast[];
}

export class ForecastProcessingInternalError extends InternalError {
  constructor(message: string) {
    super(`Unexpected error during the forecast processing: ${message}`);
  }
}

export interface BeachForecast extends Beach, ForecastPoint {}

export class Forecast {
  constructor(protected stormGlass = new StormGlass()) {}

  public async processForecastForBeaches(
    beaches: Beach[]
  ): Promise<TimeForecast[]> {
    const pointsWithCorrectSources: BeachForecast[] = [];
    try {
      for (const beach of beaches) {
        const points = await this.stormGlass.fetchPoints(beach.lat, beach.lng);
        pointsWithCorrectSources.push(...this.enrichedBeachData(points, beach));
      }
      return this.mapForecastByTime(pointsWithCorrectSources);
    } catch (error) {
      throw new ForecastProcessingInternalError(error.message);
    }
  }

  private enrichedBeachData(
    points: ForecastPoint[],
    beach: Beach
  ): BeachForecast[] {
    return points.map((point) => ({
      lat: beach.lat,
      lng: beach.lng,
      name: beach.name,
      position: beach.position,
      rating: 1,
      ...point,
    }));
  }

  private mapForecastByTime(forecast: BeachForecast[]): TimeForecast[] {
    return forecast.reduce(
      (
        forecastByTime: TimeForecast[],
        point: BeachForecast
      ): TimeForecast[] => {
        const timePointIdx = forecastByTime.findIndex(
          (f) => f.time === point.time
        );
        if (timePointIdx !== -1) {
          forecastByTime[timePointIdx].forecast.push(point);
          return forecastByTime;
        }
        forecastByTime.push({
          time: point.time,
          forecast: [point],
        });
        return forecastByTime;
      },
      []
    );
  }
}
